#pragma once

#include <memory>
#include <string>
#include <vector>

#include "client.hpp"
#include "link.hpp"
#include "sync.hpp"

namespace nw {

// Sans-IO transfer of one file of a node, original or variant, in 4 MiB chunks through presigned
// URLs. The file is named by its object id, which the node's file list must hold; its size and
// chunk count come from that entry. Chunks are presigned in windows so long transfers do not
// outlive their URLs.
class BlobTransfer {
 public:
  enum class State { RequestReady, NeedChunk, ChunkReady, Finished, Failed };

  // NotFound: the node does not list the object.
  static Result<std::unique_ptr<BlobTransfer>> beginUpload(Client& client, const std::string& nodeId,
                                                           const std::string& objectId);
  static Result<std::unique_ptr<BlobTransfer>> beginDownload(Client& client, const std::string& nodeId,
                                                             const std::string& objectId);
  // Download for a link share: presigned through POST /links/{id}/presign, no account.
  static Result<std::unique_ptr<BlobTransfer>> beginLinkDownload(LinkReader& reader, const std::string& linkId,
                                                                 const std::string& nodeId,
                                                                 const std::string& objectId);

  State state();
  const HttpRequest& request() const { return request_; }
  uint32_t chunkIndex() const { return chunkIndex_; }
  Status failure() const { return failure_; }

  // Upload: plaintext for the chunk reported by NeedChunk.
  Status provideChunk(ByteView plaintext);
  Status handleResponse(const HttpResponse& response);
  // Download: the decrypted chunk reported by ChunkReady.
  Bytes takeChunk();

 private:
  BlobTransfer() = default;
  void prepareNextStep();
  void requestPresign();
  Status handlePresign(const HttpResponse& response);
  Status handleChunkUpload(const HttpResponse& response);
  Status handleChunkDownload(const HttpResponse& response);
  std::string urlFor(uint32_t index) const;
  bool isFinalChunk(uint32_t index) const;
  Status fail(Status status);

  enum class Mode { Upload, Download };
  enum class Awaiting { Nothing, Presign, ChunkTransfer };

  Mode mode_ = Mode::Upload;
  State state_ = State::RequestReady;
  Awaiting awaiting_ = Awaiting::Nothing;
  std::string nodeId_;
  std::string objectId_;
  std::string presignPath_ = "/api/v1/blobs/presign";
  std::vector<SymmetricKey> candidateKeys_;
  uint64_t totalSize_ = 0;
  uint32_t chunkCount_ = 0;
  uint32_t nextChunk_ = 0;
  uint32_t chunkIndex_ = 0;
  std::vector<PresignedUrl> window_;
  HttpRequest request_;
  Bytes pendingPlaintext_;
  Status failure_ = Status::Ok;
};

}  // namespace nw
