package global

const (
	ERR_JSON_MARSHAL_FAILED = 400
	ERR_HTTP_PARSE_FAILED = 401
	ERR_PANIC = 500
)

const (
	KMsgTypeLogin       = 1
	KMsgTypeLogout      = 2
	KMsgTypeGetVlanInfo = 3
)

const (
	USER_RET_ERR_OK                           = 0
	USER_RET_ERR_USERNAME_INVALID             = 1
	USER_RET_ERR_USERSTAT_ERROR               = 2
	USER_RET_ERR_USERPASSWD_ERROR             = 3
	USER_RET_ERR_CARDUSER_DYNAMICPASSWD_ERROR = 4
	USER_RET_ERR_PARSE_FAILED                 = 5
	USER_RET_ERR_GENERATE_SIDFAILED           = 6
	USER_RET_ERR_USERIP_NOTMATCHED            = 7
	USER_RET_ERR_ACNAME_NOTMATCHED            = 8
	USER_RET_ERR_ACIP_NOTMATCHED              = 9
	USER_RET_ERR_DB_ACCESSFAILED              = 10
	USER_RET_ERR_DB_USERNOTEXIST              = 11
	USER_RET_ERR_CHALLENGE_REFUSED            = 12
	USER_RET_ERR_BAS_LOGINFAILED              = 13
	USER_RET_ERR_BAS_LOGOUTFAILED             = 14
	USER_RET_ERR_BAS_LOGIN_REFUSED            = 15
	USER_RET_ERR_BAS_CONNECTCREATED           = 16
	USER_RET_ERR_BAS_SAMEUSERAUTHING          = 17
	USER_RET_ERR_BAS_LOGOUT_REFUSED           = 18
	USER_RET_ERR_CONNERR_AIPS                 = 19
	USER_RET_ERR_CREATEPACKET_FAILED          = 20
	USER_RET_ERR_INIT_UDPPEER_FAILED          = 21
	USER_RET_ERR_SEND_FAILED                  = 22
	USER_RET_ERR_UNKNOWN                      = 23
)

var USER_RET_DESC = []string{
	"success",
	"username error",
	"user status error",
	"user password error",
	"card user can't apply dynamic password",
	"ur packet parse failed",
	"generate new session id failed",
	"user ip address do not matched",
	"ac name do not matched",
	"ac ip do not matched",
	"database access failed",
	"user is not exist",
	"access obs failed",
	"login bas failed",
	"logout bas failed",
	"login refused",
	"connection created",
	"same user authing",
	"logout refused",
	"connect aips",
	"create ur rsp packet failed",
	"init udppeer object failed",
	"send udp packet failed or timeout",
	"unknown error.",
}