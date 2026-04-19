package platformbinding

type ListParams struct {
	Page     int
	PageSize int
}

func normalizeListParams(params ListParams) ListParams {
	if params.Page < 1 {
		params.Page = 1
	}
	if params.PageSize < 1 || params.PageSize > 100 {
		params.PageSize = 20
	}
	return params
}

func pageOffset(params ListParams) int {
	return (params.Page - 1) * params.PageSize
}
