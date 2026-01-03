require_relative './thl01_saved_query_check'

def check(handles:, resources:, maximum_score:)
  Thl01SavedQueryCheck.run(
    handles: handles,
    resources: resources,
    maximum_score: maximum_score,
    saved_title: "THL01-Step2-IAM-Policy-Updates"
  )
end
