#include <map>

#include "query.hpp"
#include "query_fields.hpp"

namespace nw {

namespace {

// The entries a filter object names: the fields of the queried model, or the members of one of its
// File fields or the fields of a message element of one of its list fields.
struct Scope {
  const ModelDescriptor* model = nullptr;
  bool inMembers = false;
  // The field whose members `model` lists.
  uint32_t memberOwnerOrdinal = 0;

  bool inFile() const { return inMembers && model == &fileModel(); }
};

struct Context {
  const ModelDescriptor* model = nullptr;
  CodecError* error = nullptr;
  Scope scope;
};

Context fileContext(const Context& context, const FieldDescriptor& field) {
  Context inner = context;
  inner.scope = Scope{&fileModel(), true, field.ordinal};
  return inner;
}

Context messageContext(const Context& context, const FieldDescriptor& list) {
  Context inner = context;
  inner.scope = Scope{list.value.model, true, list.ordinal};
  return inner;
}

Status fail(const Context& context, const std::string& path, const std::string& reason) {
  context.error->status = Status::InvalidArgument;
  context.error->path = path;
  context.error->reason = reason;
  return Status::InvalidArgument;
}

Condition conjunction(std::vector<Condition> children) {
  if (children.size() == 1) {
    return std::move(children.front());
  }
  Condition condition;
  condition.type = Condition::Type::All;
  condition.children = std::move(children);
  return condition;
}

Condition elementsOf(Quantifier quantifier, const FieldDescriptor& list, Condition element) {
  Condition condition;
  condition.type = Condition::Type::Elements;
  condition.quantifier = quantifier;
  condition.listOrdinal = list.ordinal;
  condition.children.push_back(std::move(element));
  return condition;
}

Condition negation(Condition child) {
  Condition condition;
  condition.type = Condition::Type::Not;
  condition.children.push_back(std::move(child));
  return condition;
}

const std::map<std::string, FilterOperator>& operatorNames() {
  static const std::map<std::string, FilterOperator> names = {
      {"equals", FilterOperator::Equals}, {"not", FilterOperator::Not},
      {"in", FilterOperator::In},         {"notIn", FilterOperator::NotIn},
      {"lt", FilterOperator::Lt},         {"lte", FilterOperator::Lte},
      {"gt", FilterOperator::Gt},         {"gte", FilterOperator::Gte},
      {"contains", FilterOperator::Contains},
      {"startsWith", FilterOperator::StartsWith},
      {"endsWith", FilterOperator::EndsWith},
  };
  return names;
}

bool isOrderingOperator(FilterOperator filterOperator) {
  return filterOperator == FilterOperator::Lt || filterOperator == FilterOperator::Lte ||
         filterOperator == FilterOperator::Gt || filterOperator == FilterOperator::Gte;
}

bool isTextOperator(FilterOperator filterOperator) {
  return filterOperator == FilterOperator::Contains || filterOperator == FilterOperator::StartsWith ||
         filterOperator == FilterOperator::EndsWith;
}

bool isListOperator(FilterOperator filterOperator) {
  return filterOperator == FilterOperator::In || filterOperator == FilterOperator::NotIn;
}

bool operatorFits(FilterOperator filterOperator, FieldType type) {
  if (isOrderingOperator(filterOperator)) {
    return isOrdered(type);
  }
  if (isTextOperator(filterOperator)) {
    return type == FieldType::Text;
  }
  return true;
}

Result<std::optional<Comparable>> compileOperand(const Context& context, const FieldDescriptor& field, FieldType type,
                                                 const Json& json, const std::string& path) {
  if (json.is_null()) {
    return std::optional<Comparable>();
  }
  std::optional<Comparable> operand = toComparable(json, field, type);
  if (!operand.has_value()) {
    return fail(context, path, "is not a valid value for field " + field.name);
  }
  return operand;
}

struct FieldFilter {
  const FieldDescriptor* field = nullptr;
  FieldType type = FieldType::Text;
  uint32_t ordinal = 0;
  uint32_t member = kWholeValue;
  bool insensitive = false;
  // Only equals, not, in and notIn apply.
  bool equalityOnly = false;
};

Result<Condition> compileOperators(const Context& context, const FieldFilter& filter, const Json& operators,
                                   const std::string& path);

Result<std::vector<std::optional<Comparable>>> compileOperands(const Context& context, const FieldFilter& filter,
                                                               FilterOperator filterOperator, const Json& value,
                                                               const std::string& path) {
  std::vector<std::optional<Comparable>> operands;
  if (!isListOperator(filterOperator)) {
    Result<std::optional<Comparable>> operand = compileOperand(context, *filter.field, filter.type, value, path);
    if (!operand.ok()) {
      return operand.status();
    }
    operands.push_back(operand.take());
    return operands;
  }
  if (!value.is_array()) {
    return fail(context, path, "expects an array");
  }
  for (size_t index = 0; index < value.size(); ++index) {
    std::string elementPath = path + "[" + std::to_string(index) + "]";
    Result<std::optional<Comparable>> operand =
        compileOperand(context, *filter.field, filter.type, value[index], elementPath);
    if (!operand.ok()) {
      return operand.status();
    }
    operands.push_back(operand.take());
  }
  return operands;
}

void foldOperands(FieldTest& test) {
  for (std::optional<Comparable>& operand : test.operands) {
    if (operand.has_value() && operand->kind == Comparable::Kind::Text) {
      operand->text = lowercaseAscii(operand->text);
    }
  }
}

Result<Condition> compileOperator(const Context& context, const FieldFilter& filter, const std::string& name,
                                  const Json& value, const std::string& path) {
  auto found = operatorNames().find(name);
  if (found == operatorNames().end()) {
    return fail(context, path, "unknown operator " + name);
  }
  FilterOperator filterOperator = found->second;
  if (filterOperator == FilterOperator::Not && value.is_object()) {
    Result<Condition> nested = compileOperators(context, filter, value, path);
    if (!nested.ok()) {
      return nested;
    }
    return negation(nested.take());
  }
  bool fits = operatorFits(filterOperator, filter.type);
  bool equality = filterOperator == FilterOperator::Equals || filterOperator == FilterOperator::Not || isListOperator(filterOperator);
  if (!fits || (filter.equalityOnly && !equality)) {
    return fail(context, path, "operator " + name + " does not apply to field " + filter.field->name);
  }
  Result<std::vector<std::optional<Comparable>>> operands = compileOperands(context, filter, filterOperator, value, path);
  if (!operands.ok()) {
    return operands.status();
  }
  bool needsValue = isOrderingOperator(filterOperator) || isTextOperator(filterOperator);
  if (needsValue && !operands.value().front().has_value()) {
    return fail(context, path, "operator " + name + " cannot compare with null");
  }
  Condition condition;
  condition.type = Condition::Type::Field;
  condition.test.ordinal = filter.ordinal;
  condition.test.member = filter.member;
  condition.test.filterOperator = filterOperator;
  condition.test.operands = operands.take();
  condition.test.insensitive = filter.insensitive;
  if (filter.insensitive) {
    foldOperands(condition.test);
  }
  return condition;
}

Status readMode(const Context& context, FieldFilter& filter, const Json& operators, const std::string& path) {
  auto mode = operators.find("mode");
  if (mode == operators.end()) {
    return Status::Ok;
  }
  std::string modePath = path + ".mode";
  bool known = mode->is_string() && (mode->get<std::string>() == "default" || mode->get<std::string>() == "insensitive");
  if (!known) {
    return fail(context, modePath, "must be \"default\" or \"insensitive\"");
  }
  if (filter.type != FieldType::Text) {
    return fail(context, modePath, "applies to text fields only");
  }
  filter.insensitive = mode->get<std::string>() == "insensitive";
  return Status::Ok;
}

Result<Condition> compileOperators(const Context& context, const FieldFilter& inherited, const Json& operators,
                                   const std::string& path) {
  FieldFilter filter = inherited;
  Status modeRead = readMode(context, filter, operators, path);
  if (modeRead != Status::Ok) {
    return modeRead;
  }
  std::vector<Condition> tests;
  for (const auto& [name, value] : operators.items()) {
    if (name == "mode") {
      continue;
    }
    Result<Condition> test = compileOperator(context, filter, name, value, path + "." + name);
    if (!test.ok()) {
      return test;
    }
    tests.push_back(test.take());
  }
  return conjunction(std::move(tests));
}

Result<Condition> compileFieldFilter(const Context& context, const FieldFilter& filter, const Json& value,
                                     const std::string& path) {
  if (value.is_object()) {
    return compileOperators(context, filter, value, path);
  }
  Json equals = Json::object();
  equals["equals"] = value;
  return compileOperators(context, filter, equals, path);
}

FieldFilter filterOf(const Context& context, const FieldDescriptor& field, FieldType type) {
  FieldFilter filter;
  filter.field = &field;
  filter.type = type;
  filter.ordinal = field.ordinal;
  if (context.scope.inMembers) {
    filter.ordinal = context.scope.memberOwnerOrdinal;
    filter.member = field.ordinal;
  }
  return filter;
}

Result<Condition> compileValueField(const Context& context, const FieldDescriptor& field, const Json& value,
                                    const std::string& path) {
  std::optional<FieldType> type = filterableType(field);
  bool memberAllowed = !context.scope.inFile() || isFilterableFileMember(field);
  if (!type.has_value() || !memberAllowed) {
    return fail(context, path, "field " + field.name + " cannot be filtered");
  }
  return compileFieldFilter(context, filterOf(context, field, *type), value, path);
}

Result<Condition> compileWhere(const Context& context, const Json& json, const std::string& path);

Result<Condition> compileFileField(const Context& context, const FieldDescriptor& field, const Json& value,
                                   const std::string& path) {
  if (!value.is_object()) {
    return fail(context, path, "expects an object of name, mediaType and size filters");
  }
  return compileWhere(fileContext(context, field), value, path);
}

Result<Condition> compileMessageElement(const Context& context, const FieldDescriptor& list, const Json& value,
                                        const std::string& path) {
  if (!value.is_object()) {
    return fail(context, path, "expects an object of filters on the fields of " + list.value.model->name);
  }
  return compileWhere(messageContext(context, list), value, path);
}

// The condition one element of the list `field` has to meet.
Result<Condition> compileElement(const Context& context, const FieldDescriptor& field, const Json& value,
                                 const std::string& path) {
  if (isFile(field)) {
    return compileFileField(context, field, value, path);
  }
  if (isMessage(field)) {
    return compileMessageElement(context, field, value, path);
  }
  return compileFieldFilter(context, filterOf(context, field, *valueType(field)), value, path);
}

Result<Condition> compileHas(const Context& context, const FieldDescriptor& field, const Json& value,
                             const std::string& path) {
  if (!valueType(field).has_value()) {
    return fail(context, path, "has applies to lists of plain values, use some with a filter on the members");
  }
  Result<Condition> equals =
      compileOperator(context, filterOf(context, field, *valueType(field)), "equals", value, path);
  if (!equals.ok()) {
    return equals;
  }
  return elementsOf(Quantifier::Some, field, equals.take());
}

const std::map<std::string, Quantifier>& quantifierNames() {
  static const std::map<std::string, Quantifier> names = {
      {"some", Quantifier::Some}, {"every", Quantifier::Every}, {"none", Quantifier::None}};
  return names;
}

Result<Condition> compileListOperator(const Context& context, const FieldDescriptor& field, const std::string& name,
                                      const Json& value, const std::string& path) {
  if (name == "has") {
    return compileHas(context, field, value, path);
  }
  auto quantifier = quantifierNames().find(name);
  if (quantifier == quantifierNames().end()) {
    return fail(context, path, "unknown list operator " + name + ", expected some, every, none or has");
  }
  Result<Condition> element = compileElement(context, field, value, path);
  if (!element.ok()) {
    return element;
  }
  return elementsOf(quantifier->second, field, element.take());
}

Result<Condition> compileListField(const Context& context, const FieldDescriptor& field, const Json& value,
                                   const std::string& path) {
  if (!isFile(field) && !isMessage(field) && !valueType(field).has_value()) {
    return fail(context, path, "field " + field.name + " cannot be filtered");
  }
  if (!value.is_object()) {
    return fail(context, path, "list field " + field.name + " takes some, every, none or has");
  }
  std::vector<Condition> tests;
  for (const auto& [name, operand] : value.items()) {
    Result<Condition> test = compileListOperator(context, field, name, operand, path + "." + name);
    if (!test.ok()) {
      return test;
    }
    tests.push_back(test.take());
  }
  return conjunction(std::move(tests));
}

Result<Condition> compileField(const Context& context, const std::string& name, const Json& value,
                               const std::string& path) {
  const FieldDescriptor* field = context.scope.model->fieldByName(name);
  if (field == nullptr) {
    return fail(context, path, "unknown field " + name + " on " + context.scope.model->name);
  }
  if (context.scope.inMembers && (isFile(*field) || isList(*field))) {
    return fail(context, path, "field " + name + " cannot be filtered");
  }
  if (isFile(*field) && field->container.kind == ContainerKind::Singular) {
    return compileFileField(context, *field, value, path);
  }
  if (isList(*field)) {
    return compileListField(context, *field, value, path);
  }
  return compileValueField(context, *field, value, path);
}

Result<std::vector<Condition>> compileConditionList(const Context& context, const Json& value, const std::string& path) {
  std::vector<Condition> conditions;
  if (value.is_object()) {
    Result<Condition> single = compileWhere(context, value, path);
    if (!single.ok()) {
      return single.status();
    }
    conditions.push_back(single.take());
    return conditions;
  }
  if (!value.is_array()) {
    return fail(context, path, "expects an object or an array of objects");
  }
  for (size_t index = 0; index < value.size(); ++index) {
    Result<Condition> element = compileWhere(context, value[index], path + "[" + std::to_string(index) + "]");
    if (!element.ok()) {
      return element.status();
    }
    conditions.push_back(element.take());
  }
  return conditions;
}

Result<Condition> compileLogical(const Context& context, const std::string& name, const Json& value,
                                 const std::string& path) {
  Result<std::vector<Condition>> conditions = compileConditionList(context, value, path);
  if (!conditions.ok()) {
    return conditions.status();
  }
  if (name == "AND") {
    return conjunction(conditions.take());
  }
  if (name == "OR") {
    Condition any;
    any.type = Condition::Type::Any;
    any.children = conditions.take();
    return any;
  }
  std::vector<Condition> negated;
  for (Condition& condition : conditions.value()) {
    negated.push_back(negation(std::move(condition)));
  }
  return conjunction(std::move(negated));
}

Result<Condition> compileEntry(const Context& context, const std::string& name, const Json& value,
                               const std::string& path) {
  if (name == "AND" || name == "OR" || name == "NOT") {
    return compileLogical(context, name, value, path);
  }
  return compileField(context, name, value, path);
}

Result<Condition> compileWhere(const Context& context, const Json& json, const std::string& path) {
  if (!json.is_object()) {
    return fail(context, path, "expects an object");
  }
  std::vector<Condition> conditions;
  for (const auto& [name, value] : json.items()) {
    Result<Condition> entry = compileEntry(context, name, value, path + "." + name);
    if (!entry.ok()) {
      return entry;
    }
    conditions.push_back(entry.take());
  }
  return conjunction(std::move(conditions));
}

Result<bool> compileDirection(const Context& context, const Json& direction, const std::string& path) {
  bool valid = direction.is_string() && (direction == "asc" || direction == "desc");
  if (!valid) {
    return fail(context, path, "must be \"asc\" or \"desc\"");
  }
  return direction == "desc";
}

Status compileMemberOrder(const Context& context, const FieldDescriptor& field, const Json& members,
                          const std::string& path, std::vector<OrderKey>& keys) {
  if (!members.is_object()) {
    return fail(context, path, "expects an object of name, mediaType or size and a direction");
  }
  for (const auto& [name, direction] : members.items()) {
    std::string memberPath = path + "." + name;
    const FieldDescriptor* member = fileModel().fieldByName(name);
    if (member == nullptr || !isFilterableFileMember(*member)) {
      return fail(context, memberPath, "member " + name + " of " + field.name + " cannot be ordered");
    }
    Result<bool> descending = compileDirection(context, direction, memberPath);
    if (!descending.ok()) {
      return descending.status();
    }
    keys.push_back(OrderKey{field.ordinal, member->ordinal, descending.value()});
  }
  return Status::Ok;
}

Status compileValueOrder(const Context& context, const FieldDescriptor& field, const Json& direction,
                         const std::string& path, std::vector<OrderKey>& keys) {
  if (!filterableType(field).has_value()) {
    return fail(context, path, "field " + field.name + " cannot be ordered");
  }
  Result<bool> descending = compileDirection(context, direction, path);
  if (!descending.ok()) {
    return descending.status();
  }
  keys.push_back(OrderKey{field.ordinal, kWholeValue, descending.value()});
  return Status::Ok;
}

Status compileOrderKey(const Context& context, const FieldDescriptor& field, const Json& direction,
                       const std::string& path, std::vector<OrderKey>& keys) {
  if (isFile(field) && field.container.kind == ContainerKind::Singular) {
    return compileMemberOrder(context, field, direction, path, keys);
  }
  return compileValueOrder(context, field, direction, path, keys);
}

Status compileOrderKeys(const Context& context, const Json& entry, const std::string& path, std::vector<OrderKey>& keys) {
  if (!entry.is_object()) {
    return fail(context, path, "expects an object of field and direction");
  }
  for (const auto& [name, direction] : entry.items()) {
    std::string keyPath = path + "." + name;
    const FieldDescriptor* field = context.model->fieldByName(name);
    if (field == nullptr) {
      return fail(context, keyPath, "unknown field " + name + " on " + context.model->name);
    }
    Status compiled = compileOrderKey(context, *field, direction, keyPath, keys);
    if (compiled != Status::Ok) {
      return compiled;
    }
  }
  return Status::Ok;
}

Result<std::vector<OrderKey>> compileOrderBy(const Context& context, const Json& json, const std::string& path) {
  std::vector<OrderKey> keys;
  if (json.is_object()) {
    Status compiled = compileOrderKeys(context, json, path, keys);
    if (compiled != Status::Ok) {
      return compiled;
    }
    return keys;
  }
  if (!json.is_array()) {
    return fail(context, path, "expects an object or an array of objects");
  }
  for (size_t index = 0; index < json.size(); ++index) {
    Status compiled = compileOrderKeys(context, json[index], path + "[" + std::to_string(index) + "]", keys);
    if (compiled != Status::Ok) {
      return compiled;
    }
  }
  return keys;
}

Status compileTake(const Context& context, const Json& json, Query& query) {
  if (!json.is_number_unsigned()) {
    return fail(context, "take", "must be a non-negative integer");
  }
  query.take = json.get<size_t>();
  return Status::Ok;
}

Status compileIncludedField(const Context& context, const std::string& name, const Json& flag, Query& query) {
  std::string path = "include." + name;
  const FieldDescriptor* field = context.model->fieldByName(name);
  bool singleReference = field != nullptr && field->value.kind == ValueKind::Reference &&
                         field->container.kind == ContainerKind::Singular;
  if (!singleReference) {
    return fail(context, path, "include names a single ref field of " + context.model->name);
  }
  if (!flag.is_boolean()) {
    return fail(context, path, "must be true or false");
  }
  if (flag.get<bool>()) {
    query.include.push_back(IncludedField{field->ordinal, name});
  }
  return Status::Ok;
}

Status compileInclude(const Context& context, const Json& json, Query& query) {
  if (!json.is_object()) {
    return fail(context, "include", "expects an object of ref fields");
  }
  for (const auto& [name, flag] : json.items()) {
    Status compiled = compileIncludedField(context, name, flag, query);
    if (compiled != Status::Ok) {
      return compiled;
    }
  }
  return Status::Ok;
}

Status compileSection(const Context& context, const std::string& name, const Json& value, Query& query) {
  if (name == "where") {
    Result<Condition> where = compileWhere(context, value, "where");
    if (!where.ok()) {
      return where.status();
    }
    query.where = where.take();
    return Status::Ok;
  }
  if (name == "orderBy") {
    Result<std::vector<OrderKey>> orderBy = compileOrderBy(context, value, "orderBy");
    if (!orderBy.ok()) {
      return orderBy.status();
    }
    query.orderBy = orderBy.take();
    return Status::Ok;
  }
  if (name == "take") {
    return compileTake(context, value, query);
  }
  if (name == "include") {
    return compileInclude(context, value, query);
  }
  return fail(context, name, "unknown query key " + name + ", expected where, orderBy, take or include");
}

}  // namespace

Result<Query> compileQuery(const Json& json, const ModelDescriptor& model, CodecError& error) {
  error = CodecError{};
  Context context;
  context.model = &model;
  context.error = &error;
  context.scope.model = &model;
  if (!json.is_object()) {
    return fail(context, "", "a query is an object with where, orderBy, take and include");
  }
  Query query;
  for (const auto& [name, value] : json.items()) {
    Status compiled = compileSection(context, name, value, query);
    if (compiled != Status::Ok) {
      return compiled;
    }
  }
  return query;
}

}  // namespace nw
