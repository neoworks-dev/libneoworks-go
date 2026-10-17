#pragma once

#include <optional>
#include <vector>

#include "field_index.hpp"
#include "query.hpp"

// Reads the sorted indexes of a table instead of all its rows. The plan only narrows which rows are
// looked at and in what order; every candidate is still tested against the whole `where`, so a
// query returns the same rows with or without an index.
namespace nw {

struct IndexScan {
  const SortedIndex* index = nullptr;
  // The entries from `lower` up to `upper`.
  IndexProbe lower;
  IndexProbe upper;
  // The index order already is the `orderBy` order, apart from rows with equal order values, which
  // go by id. Descending reads the entries backwards.
  bool ordersResult = false;
  bool descending = false;
  // How many leading index parts the order values and the equality prefix take up together.
  size_t orderPartCount = 0;
};

// The scan over the index of `indexes` that equality and range tests on its leading fields and the
// `orderBy` use best; nullopt when no index helps. The scan points at operands inside `query`.
std::optional<IndexScan> planIndexScan(const Query& query, const std::vector<SortedIndex>& indexes);

}  // namespace nw
