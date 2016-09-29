package global

func GetUserRetDesc(code int32) string {
	if code > USER_RET_ERR_UNKNOWN || code < USER_RET_ERR_OK {
		return "unknow err."
	}
	return USER_RET_DESC[code]
}
