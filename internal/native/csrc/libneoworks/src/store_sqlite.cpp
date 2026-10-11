#include <sqlite3.h>

#include "store.hpp"

namespace nw {

namespace {

class StatementHandle {
 public:
  StatementHandle(sqlite3* database, const char* sql) {
    if (sqlite3_prepare_v2(database, sql, -1, &statement_, nullptr) != SQLITE_OK) {
      statement_ = nullptr;
    }
  }
  ~StatementHandle() { sqlite3_finalize(statement_); }
  StatementHandle(const StatementHandle&) = delete;
  StatementHandle& operator=(const StatementHandle&) = delete;

  sqlite3_stmt* get() const { return statement_; }
  bool valid() const { return statement_ != nullptr; }

 private:
  sqlite3_stmt* statement_ = nullptr;
};

class SqliteBackend : public RecordBackend {
 public:
  explicit SqliteBackend(const std::string& path) {
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    if (sqlite3_open_v2(path.c_str(), &database_, flags, nullptr) != SQLITE_OK) {
      sqlite3_close(database_);
      database_ = nullptr;
      return;
    }
    sqlite3_exec(database_, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;", nullptr,
                 nullptr, nullptr);
    const char* schema =
        "CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, key TEXT NOT NULL, value BLOB NOT NULL, "
        "PRIMARY KEY (kind, key)) WITHOUT ROWID;";
    if (sqlite3_exec(database_, schema, nullptr, nullptr, nullptr) != SQLITE_OK) {
      sqlite3_close(database_);
      database_ = nullptr;
    }
  }

  ~SqliteBackend() override { sqlite3_close(database_); }

  bool usable() const { return database_ != nullptr; }

  Status put(std::string_view kind, std::string_view key, ByteView value) override {
    if (database_ == nullptr) {
      return Status::IoFailure;
    }
    StatementHandle statement(database_, "INSERT OR REPLACE INTO records (kind, key, value) VALUES (?1, ?2, ?3)");
    if (!statement.valid()) {
      return Status::IoFailure;
    }
    sqlite3_bind_text(statement.get(), 1, kind.data(), static_cast<int>(kind.size()), SQLITE_STATIC);
    sqlite3_bind_text(statement.get(), 2, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);
    sqlite3_bind_blob64(statement.get(), 3, value.data(), value.size(), SQLITE_STATIC);
    return finish(statement);
  }

  Status remove(std::string_view kind, std::string_view key) override {
    if (database_ == nullptr) {
      return Status::IoFailure;
    }
    StatementHandle statement(database_, "DELETE FROM records WHERE kind = ?1 AND key = ?2");
    if (!statement.valid()) {
      return Status::IoFailure;
    }
    sqlite3_bind_text(statement.get(), 1, kind.data(), static_cast<int>(kind.size()), SQLITE_STATIC);
    sqlite3_bind_text(statement.get(), 2, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);
    return finish(statement);
  }

  Status visitAll(const Visitor& visitor) override {
    if (database_ == nullptr) {
      return Status::IoFailure;
    }
    StatementHandle statement(database_, "SELECT kind, key, value FROM records");
    if (!statement.valid()) {
      return Status::IoFailure;
    }
    while (sqlite3_step(statement.get()) == SQLITE_ROW) {
      visitRow(statement.get(), visitor);
    }
    return Status::Ok;
  }

  Status clear() override {
    if (database_ == nullptr) {
      return Status::IoFailure;
    }
    if (sqlite3_exec(database_, "DELETE FROM records", nullptr, nullptr, nullptr) != SQLITE_OK) {
      return Status::IoFailure;
    }
    return Status::Ok;
  }

 private:
  static Status finish(StatementHandle& statement) {
    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
      return Status::IoFailure;
    }
    return Status::Ok;
  }

  static void visitRow(sqlite3_stmt* row, const Visitor& visitor) {
    const char* kind = reinterpret_cast<const char*>(sqlite3_column_text(row, 0));
    const char* key = reinterpret_cast<const char*>(sqlite3_column_text(row, 1));
    const uint8_t* value = static_cast<const uint8_t*>(sqlite3_column_blob(row, 2));
    size_t valueLength = static_cast<size_t>(sqlite3_column_bytes(row, 2));
    visitor(kind, key, ByteView(value, valueLength));
  }

  sqlite3* database_ = nullptr;
};

}  // namespace

std::unique_ptr<RecordBackend> makeSqliteBackend(const std::string& path) {
  auto backend = std::make_unique<SqliteBackend>(path);
  if (!backend->usable()) {
    return nullptr;
  }
  return backend;
}

}  // namespace nw
