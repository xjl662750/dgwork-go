package dgwork

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/mitchellh/mapstructure"
)

const (
	// DGBaseURL api基础路由
	DGBaseURL = "https://openplatform.dg-work.cn"
)

// Token Token
type Token struct {
	ExpiresIn   int    `json:"expiresIn"`   // 过期时间
	AccessToken string `json:"accessToken"` // 获取到的凭证
}

// Cache Cache
type Cache interface {
	Get(key string) interface{}
	GetMulti(keys []string) []interface{}
	Put(key string, val interface{}, timeout time.Duration) error
	Delete(key string) error
	Incr(key string) error
	Decr(key string) error
	IsExist(key string) bool
	ClearAll() error
	StartAndGC(config string) error
}

// Client 主要处理Client
type Client struct {
	AppKey        string
	AppSecret     string
	CacheToken    Token
	cacheProvider Cache
}

// NewClient NewClient
func NewClient(AppKey, AppSecret string, cacheProvider Cache) (client *Client) {
	client = &Client{
		AppKey:    AppKey,
		AppSecret: AppSecret,
	}
	return
}

// GetToken  获取access_token
// 应该全局缓存该token，不能频繁刷新
// https://openplatform-portal.dg-work.cn/#/docs?apiType=serverapi&docKey=2674862
func (c *Client) GetToken() (t Token, err error) {
	if c.cacheProvider != nil {
		token, ok := c.cacheProvider.Get(c.AppKey + "_access_token").(string)
		if ok {
			c.CacheToken.AccessToken = token
			t = c.CacheToken
			return
		}
	}
	t, err = c.RefreshToken()
	return
}

// RefreshToken 刷新access_token
func (c *Client) RefreshToken() (t Token, err error) {
	params := url.Values{}
	params.Add("appsecret", c.AppSecret)
	params.Add("appkey", c.AppKey)
	var commonReply CommonReply
	err = c.getJSON(fmt.Sprintf("%s/gettoken.json", DGBaseURL),
		params.Encode(), &commonReply)
	data, err := commonReply.GetData()
	if err != nil {
		return
	}
	err = mapstructure.Decode(data, &t)
	if err != nil {
		return
	}
	if c.cacheProvider != nil {
		c.cacheProvider.Delete(c.AppKey + "_access_token") // 删除老的 添加新的
		c.cacheProvider.Put(c.AppKey+"_access_token", t.AccessToken, time.Duration(t.ExpiresIn))
	}
	c.CacheToken = t
	return
}
func (c *Client) getJSON(getURL, params string, out interface{}) error {
	if params != "" {
		getURL = getURL + "?" + params
	}
	req, _ := http.NewRequest("GET", getURL, nil)
	mac := GetFirstMacAddress()
	ip := GetFirstIP()
	timestamp := time.Now().Format("2006-01-02T15:04:05.999999+08:00")
	nonce := strconv.FormatInt(time.Now().UnixNano()/100, 10)
	message := "GET\n" + timestamp + "\n" + nonce + "\n" + req.URL.Path
	if params != "" {
		message = message + "\n" + params
	}
	signature := ComputeHmac256(message, c.AppSecret)
	req.Header.Add("X-Hmac-Auth-Timestamp", timestamp)
	req.Header.Add("X-Hmac-Auth-Version", "1.0")
	req.Header.Add("X-Hmac-Auth-Nonce", nonce)
	req.Header.Add("apiKey", c.AppKey)
	req.Header.Add("X-Hmac-Auth-Signature", signature)
	req.Header.Add("X-Hmac-Auth-IP", ip)
	req.Header.Add("X-Hmac-Auth-MAC", mac)
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	resp, err := responseFilter(response)
	body := string(resp)
	// fmt.Println(body)
	err = jsoniter.UnmarshalFromString(body, out)

	return err
}

// ComputeHmac256 ComputeHmac256
func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// GetFirstIP 获取本机的ip地址
func GetFirstIP() (ip string) {
	ip = "127.0.0.1"
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	for _, address := range addrs {
		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
				return
			}
		}
	}
	return
}

// GetFirstMacAddress 获取本机的MAC地址
func GetFirstMacAddress() (macAddress string) {
	macAddress = "00:00:00:00:00:00"
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, inter := range interfaces {
		macAddress = inter.HardwareAddr.String()
		return
	}
	return
}
func responseFilter(response *http.Response) (resp []byte, err error) {
	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("response.Status %s", response.Status)
		return
	}
	resp, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	return
}

// CommonReply CommonReply
type CommonReply struct {
	RequestId    string   `json:"_RequestId"`
	Success      bool     `json:"success"`
	Content      *Content `json:"content"`
	Message      string   `json:"Message"` //sucess为false返回以下字段
	ErrorCode    string   `json:"errorCode"`
	HostId       string   `json:"HostId"`
	Code         string   `json:"Code"`
	BizErrorCode string   `json:"bizErrorCode"`
	ErrorMsg     string   `json:"errorMsg"`
	ErrorLevel   string   `json:"errorLevel"`
}

// Content Content
type Content struct {
	Success         bool        `json:"success"`
	Data            interface{} `json:"data"`
	ResponseMessage string      `json:"responseMessage"`
	ResponseCode    string      `json:"responseCode"`
}

// GetData GetData
func (rep CommonReply) GetData() (data interface{}, err error) {
	if rep.Success {
		if rep.Content != nil {
			if rep.Content.Success {
				data = rep.Content.Data
				return
			}
			err = errors.New(rep.Content.ResponseMessage)
			return
		}
	}
	err = errors.New(rep.ErrorMsg)
	return
}

// UserInfo UserInfo
type UserInfo struct {
	Account      string `json:"account"`      // 账号名
	AccountID    int64  `json:"accountId"`    // 账号id
	ClientId     string `json:"clientId"`     // 应用名
	EmployeeCode string `json:"employeeCode"` // 租户下人员编码
	NameSpace    string `json:"namespace"`    // 账号类型
	NickNameCn   string `json:"nickNameCn"`   // 昵称
	RealmId      int64  `json:"realmId"`      // 租户id
	RealmName    string `json:"realmName"`    // 租户名称
	LastName     string `json:"lastName"`     // 姓名
	OpenID       string `json:"openid"`       // 应用+用户唯一标识
	TenantUserId string `json:"tenantUserId"` // 租户+用户唯一标识
}

// GetUserInfo 获取成员详情
func (c *Client) GetUserInfo(code string) (info UserInfo, err error) {
	token, err := c.GetToken()
	if err != nil {
		return
	}
	params := url.Values{}
	params.Add("access_token", token.AccessToken)
	params.Add("auth_code", code)
	var commonReply CommonReply
	err = c.getJSON(DGBaseURL+"/rpc/oauth2/dingtalk_app_user.json", params.Encode(), &commonReply)
	data, err := commonReply.GetData()
	if err != nil {
		return
	}
	err = mapstructure.Decode(data, &info)
	return
}
