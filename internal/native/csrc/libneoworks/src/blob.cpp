#include "blob.hpp"

namespace nw {

namespace {

constexpr uint32_t kPresignWindow = 8;

HttpRequest apiJsonRequest(const std::string& url, const Bytes& body) {
  HttpRequest request;
  request.method = "POST";
  request.url = url;
  request.contentType = "application/json";
  request.body = body;
  return request;
}

bool isSuccess(int httpStatus) { return httpStatus >= 200 && httpStatus < 300; }

}  // namespace

Result<std::unique_ptr<BlobTransfer>> BlobTransfer::beginUpload(Client& client, const std::string& nodeId,
                                                                uint32_t variantIndex, const std::string& objectId,
                                                                uint64_t totalSize) {
  if (!isLowercaseUuid(objectId)) {
    return Status::InvalidArgument;
  }
  if (roleRank(client.effectiveRole(nodeId)) < roleRank("write")) {
    return Status::Forbidden;
  }
  const Node* node = client.database().findNode(nodeId);
  if (node == nullptr || isShortcut(*node)) {
    return Status::InvalidArgument;
  }
  Result<SymmetricKey> nodeKey = client.resolveNodeKey(nodeId);
  if (!nodeKey.ok()) {
    return nodeKey.status();
  }
  std::unique_ptr<BlobTransfer> transfer(new BlobTransfer());
  transfer->mode_ = Mode::Upload;
  transfer->nodeId_ = nodeId;
  transfer->objectId_ = objectId;
  transfer->candidateKeys_.push_back(blobKey(nodeKey.value(), variantIndex));
  transfer->totalSize_ = totalSize;
  transfer->chunkCount_ = static_cast<uint32_t>(blobChunkCount(totalSize));
  return transfer;
}

Result<std::unique_ptr<BlobTransfer>> BlobTransfer::beginDownload(Client& client, const std::string& nodeId,
                                                                  uint32_t variantIndex, const std::string& objectId,
                                                                  uint32_t chunkCount) {
  const Node* node = client.database().findNode(nodeId);
  if (node == nullptr || isShortcut(*node) || !isLowercaseUuid(objectId) || chunkCount == 0) {
    return Status::InvalidArgument;
  }
  Result<SymmetricKey> nodeKey = client.resolveNodeKey(nodeId);
  if (!nodeKey.ok()) {
    return nodeKey.status();
  }
  std::unique_ptr<BlobTransfer> transfer(new BlobTransfer());
  transfer->mode_ = Mode::Download;
  transfer->nodeId_ = nodeId;
  transfer->objectId_ = objectId;
  transfer->candidateKeys_.push_back(blobKey(nodeKey.value(), variantIndex));
  for (auto& [epoch, key] : client.keyring().allNodeKeys(nodeId)) {
    if (epoch != node->epoch) {
      transfer->candidateKeys_.push_back(blobKey(key, variantIndex));
    }
  }
  transfer->chunkCount_ = chunkCount;
  return transfer;
}

Result<std::unique_ptr<BlobTransfer>> BlobTransfer::beginLinkDownload(LinkReader& reader, const std::string& linkId,
                                                                      const std::string& nodeId, uint32_t variantIndex,
                                                                      const std::string& objectId,
                                                                      uint32_t chunkCount) {
  if (!isLowercaseUuid(objectId) || !isLowercaseUuid(linkId) || chunkCount == 0) {
    return Status::InvalidArgument;
  }
  Result<SymmetricKey> nodeKey = reader.resolveNodeKey(nodeId);
  if (!nodeKey.ok()) {
    return nodeKey.status();
  }
  std::unique_ptr<BlobTransfer> transfer(new BlobTransfer());
  transfer->mode_ = Mode::Download;
  transfer->nodeId_ = nodeId;
  transfer->objectId_ = objectId;
  transfer->presignPath_ = "/api/v1/links/" + linkId + "/presign";
  transfer->candidateKeys_.push_back(blobKey(nodeKey.value(), variantIndex));
  transfer->chunkCount_ = chunkCount;
  return transfer;
}

bool BlobTransfer::isFinalChunk(uint32_t index) const { return index + 1 == chunkCount_; }

std::string BlobTransfer::urlFor(uint32_t index) const {
  for (const PresignedUrl& entry : window_) {
    if (entry.index == index) {
      return entry.url;
    }
  }
  return std::string();
}

Status BlobTransfer::fail(Status status) {
  failure_ = status;
  state_ = State::Failed;
  return status;
}

void BlobTransfer::requestPresign() {
  std::vector<uint32_t> indexes;
  for (uint32_t index = nextChunk_; index < chunkCount_ && indexes.size() < kPresignWindow; ++index) {
    indexes.push_back(index);
  }
  bool upload = mode_ == Mode::Upload;
  request_ = apiJsonRequest(presignPath_, buildPresignRequest(nodeId_, objectId_, upload, indexes));
  awaiting_ = Awaiting::Presign;
  state_ = State::RequestReady;
}

void BlobTransfer::prepareNextStep() {
  if (nextChunk_ >= chunkCount_) {
    state_ = State::Finished;
    return;
  }
  if (urlFor(nextChunk_).empty()) {
    requestPresign();
    return;
  }
  chunkIndex_ = nextChunk_;
  if (mode_ == Mode::Upload) {
    state_ = State::NeedChunk;
    return;
  }
  request_ = HttpRequest();
  request_.method = "GET";
  request_.url = urlFor(nextChunk_);
  request_.isApi = false;
  awaiting_ = Awaiting::ChunkTransfer;
  state_ = State::RequestReady;
}

BlobTransfer::State BlobTransfer::state() {
  if (state_ == State::RequestReady && awaiting_ == Awaiting::Nothing) {
    prepareNextStep();
  }
  return state_;
}

Status BlobTransfer::provideChunk(ByteView plaintext) {
  if (state_ != State::NeedChunk || mode_ != Mode::Upload) {
    return Status::InvalidState;
  }
  bool finalChunk = isFinalChunk(chunkIndex_);
  bool sizeValid = plaintext.size() == kBlobChunkBytes;
  if (finalChunk) {
    uint64_t expectedFinalSize = totalSize_ - static_cast<uint64_t>(chunkIndex_) * kBlobChunkBytes;
    sizeValid = plaintext.size() == expectedFinalSize;
  }
  if (!sizeValid) {
    return fail(Status::InvalidArgument);
  }
  request_ = HttpRequest();
  request_.method = "PUT";
  request_.url = urlFor(chunkIndex_);
  request_.isApi = false;
  request_.contentType = "application/octet-stream";
  request_.body = encryptBlobChunk(candidateKeys_[0], nodeId_, objectId_, chunkIndex_, finalChunk, plaintext);
  awaiting_ = Awaiting::ChunkTransfer;
  state_ = State::RequestReady;
  return Status::Ok;
}

Status BlobTransfer::handlePresign(const HttpResponse& response) {
  if (!isSuccess(response.status)) {
    return fail(Status::IoFailure);
  }
  Result<std::vector<PresignedUrl>> urls = parsePresignResponse(response.body);
  if (!urls.ok()) {
    return fail(urls.status());
  }
  window_ = urls.take();
  if (urlFor(nextChunk_).empty()) {
    return fail(Status::Malformed);
  }
  awaiting_ = Awaiting::Nothing;
  return Status::Ok;
}

Status BlobTransfer::handleChunkUpload(const HttpResponse& response) {
  if (!isSuccess(response.status)) {
    return fail(Status::IoFailure);
  }
  ++nextChunk_;
  awaiting_ = Awaiting::Nothing;
  state_ = State::RequestReady;
  return Status::Ok;
}

Status BlobTransfer::handleChunkDownload(const HttpResponse& response) {
  if (!isSuccess(response.status)) {
    return fail(Status::IoFailure);
  }
  bool finalChunk = isFinalChunk(chunkIndex_);
  for (const SymmetricKey& key : candidateKeys_) {
    Result<Bytes> plaintext = decryptBlobChunk(key, nodeId_, objectId_, chunkIndex_, finalChunk, response.body);
    if (plaintext.ok()) {
      pendingPlaintext_ = plaintext.take();
      awaiting_ = Awaiting::Nothing;
      state_ = State::ChunkReady;
      return Status::Ok;
    }
  }
  return fail(Status::AuthenticationFailed);
}

Status BlobTransfer::handleResponse(const HttpResponse& response) {
  Awaiting expected = awaiting_;
  if (state_ != State::RequestReady || expected == Awaiting::Nothing) {
    return Status::InvalidState;
  }
  if (expected == Awaiting::Presign) {
    return handlePresign(response);
  }
  if (mode_ == Mode::Upload) {
    return handleChunkUpload(response);
  }
  return handleChunkDownload(response);
}

Bytes BlobTransfer::takeChunk() {
  Bytes taken = std::move(pendingPlaintext_);
  pendingPlaintext_.clear();
  ++nextChunk_;
  state_ = State::RequestReady;
  awaiting_ = Awaiting::Nothing;
  return taken;
}

}  // namespace nw
