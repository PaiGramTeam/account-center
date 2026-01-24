package response

// PageData 分页数据结构
type PageData struct {
	List       interface{} `json:"list"`        // 数据列表
	Total      int64       `json:"total"`       // 总数
	Page       int         `json:"page"`        // 当前页码
	PageSize   int         `json:"page_size"`   // 每页大小
	TotalPages int         `json:"total_pages"` // 总页数
}

// NewPageData 创建分页数据
func NewPageData(list interface{}, total int64, page, pageSize int) *PageData {
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	return &PageData{
		List:       list,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}
}

// EmptyPageData 返回空的分页数据
func EmptyPageData(page, pageSize int) *PageData {
	return &PageData{
		List:       []interface{}{},
		Total:      0,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: 0,
	}
}

// MessageData 仅包含消息的数据结构
type MessageData struct {
	Message string `json:"message"`
}

// NewMessageData 创建消息数据
func NewMessageData(message string) *MessageData {
	return &MessageData{Message: message}
}
