package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

// 支持代理的域名
var proxyDomains = []string{
	"api.openai.com",
	"api.anthropic.com",
	"generativelanguage.googleapis.com",
}

const (
	certsDir   = "certs"
	caCertFile = "certs/proxy_ca.crt"
	caKeyFile  = "certs/proxy_ca.key"
	configFile = "config.json"
)

// ==================== 数据结构 ====================

type OpenAIRequest struct {
	Model               string          `json:"model"`
	Messages            []OpenAIMessage `json:"messages"`
	MaxTokens           int             `json:"max_tokens,omitempty"`
	MaxCompletionTokens int             `json:"max_completion_tokens,omitempty"`
	Temperature         float64         `json:"temperature,omitempty"`
	TopP                float64         `json:"top_p,omitempty"`
	Stream              bool            `json:"stream,omitempty"`
	Stop                interface{}     `json:"stop,omitempty"`
	Tools               []OpenAITool    `json:"tools,omitempty"`
}

type OpenAITool struct {
	Type     string             `json:"type"`
	Function OpenAIToolFunction `json:"function"`
}

type OpenAIToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type OpenAIMessage struct {
	Role             string           `json:"role"`
	Content          interface{}      `json:"content"`
	ReasoningContent interface{}      `json:"reasoning_content,omitempty"`
	ToolCalls        []OpenAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID       string           `json:"tool_call_id,omitempty"`
	Name             string           `json:"name,omitempty"`
}

type OpenAIToolCall struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function OpenAIFunctionCall `json:"function"`
	Index    int                `json:"index,omitempty"`
}

type OpenAIFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type OpenAIResponse struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Created int64          `json:"created"`
	Model   string         `json:"model"`
	Choices []OpenAIChoice `json:"choices"`
	Usage   OpenAIUsage    `json:"usage"`
}

type OpenAIChoice struct {
	Index        int           `json:"index"`
	Message      OpenAIMessage `json:"message,omitempty"`
	Delta        OpenAIMessage `json:"delta,omitempty"`
	FinishReason string        `json:"finish_reason,omitempty"`
}

type OpenAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type OpenAIStreamChunk struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Created int64          `json:"created"`
	Model   string         `json:"model"`
	Choices []OpenAIChoice `json:"choices"`
}

type AnthropicRequest struct {
	Model         string             `json:"model"`
	MaxTokens     int                `json:"max_tokens"`
	System        string             `json:"system,omitempty"`
	Messages      []AnthropicMessage `json:"messages"`
	Temperature   float64            `json:"temperature,omitempty"`
	TopP          float64            `json:"top_p,omitempty"`
	Stream        bool               `json:"stream,omitempty"`
	StopSequences []string           `json:"stop_sequences,omitempty"`
	Tools         []AnthropicTool    `json:"tools,omitempty"`
}

type AnthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type AnthropicMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

type AnthropicResponse struct {
	ID           string             `json:"id"`
	Type         string             `json:"type"`
	Role         string             `json:"role"`
	Content      []AnthropicContent `json:"content"`
	Model        string             `json:"model"`
	StopReason   string             `json:"stop_reason"`
	StopSequence string             `json:"stop_sequence,omitempty"`
	Usage        AnthropicUsage     `json:"usage"`
}

type AnthropicContent struct {
	Type     string          `json:"type"`
	Text     string          `json:"text,omitempty"`
	Thinking string          `json:"thinking,omitempty"`
	ID       string          `json:"id,omitempty"`    // for tool_use
	Name     string          `json:"name,omitempty"`  // for tool_use
	Input    json.RawMessage `json:"input,omitempty"` // for tool_use
}

type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type AnthropicStreamEvent struct {
	Type         string             `json:"type"`
	Message      *AnthropicResponse `json:"message,omitempty"`
	Delta        *AnthropicDelta    `json:"delta,omitempty"`
	ContentBlock *AnthropicContent  `json:"content_block,omitempty"` // for content_block_start
	Index        int                `json:"index,omitempty"`
	Usage        *AnthropicUsage    `json:"usage,omitempty"`
}

type AnthropicDelta struct {
	Type        string `json:"type,omitempty"`
	Text        string `json:"text,omitempty"`
	Thinking    string `json:"thinking,omitempty"`
	StopReason  string `json:"stop_reason,omitempty"`
	PartialJson string `json:"partial_json,omitempty"` // for tool_use input
}

// ==================== Gemini 请求/响应结构 ====================

type GeminiRequest struct {
	Contents          []GeminiContent         `json:"contents"`
	SystemInstruction *GeminiContent          `json:"systemInstruction,omitempty"`
	GenerationConfig  *GeminiGenerationConfig `json:"generationConfig,omitempty"`
	Tools             []GeminiToolConfig      `json:"tools,omitempty"`
}

type GeminiToolConfig struct {
	FunctionDeclarations []GeminiFunctionDeclaration `json:"functionDeclarations,omitempty"`
}

type GeminiFunctionDeclaration struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type GeminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text         string              `json:"text,omitempty"`
	InlineData   *GeminiInlineData   `json:"inlineData,omitempty"`
	FunctionCall *GeminiFunctionCall `json:"functionCall,omitempty"`
	FunctionResp *GeminiFunctionResp `json:"functionResponse,omitempty"`
}

type GeminiInlineData struct {
	MimeType string `json:"mimeType"`
	Data     string `json:"data"`
}

type GeminiFunctionCall struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args"`
}

type GeminiFunctionResp struct {
	Name     string      `json:"name"`
	Response interface{} `json:"response"`
}

type GeminiGenerationConfig struct {
	Temperature     float64  `json:"temperature,omitempty"`
	TopP            float64  `json:"topP,omitempty"`
	MaxOutputTokens int      `json:"maxOutputTokens,omitempty"`
	StopSequences   []string `json:"stopSequences,omitempty"`
}

type GeminiResponse struct {
	Candidates    []GeminiCandidate `json:"candidates"`
	UsageMetadata *GeminiUsage      `json:"usageMetadata,omitempty"`
}

type GeminiCandidate struct {
	Content      GeminiContent `json:"content"`
	FinishReason string        `json:"finishReason,omitempty"`
}

type GeminiUsage struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// 协议模式常量
const (
	ModeOpenAI        = 0
	ModeAnthropic     = 1
	ModeOpenAIConvert = 2
)

var protocolModes = []string{"OpenAI (直连)", "Anthropic (Claude)", "OpenAI (转换)"}

type Config struct {
	TargetURL        string            `json:"target_url"`
	TargetURLHistory []string          `json:"target_url_history,omitempty"`
	ListenAddr       string            `json:"listen_addr"`
	ProtocolMode     int               `json:"protocol_mode"`
	ModelMappings    map[string]string `json:"model_mappings"`
	ShowLog          bool              `json:"show_log"`
}

// ==================== 全局变量 ====================

var (
	config          Config
	workDir         string
	mainWindow      *walk.MainWindow
	logTextEdit     *walk.TextEdit
	targetURLCombo  *walk.ComboBox
	deleteURLButton *walk.PushButton
	listenAddrEdit  *walk.LineEdit
	protocolCombo   *walk.ComboBox
	proxyButton     *walk.PushButton
	certButton      *walk.PushButton
	testButton      *walk.PushButton
	statusLabel     *walk.Label
	notifyIcon      *walk.NotifyIcon
	mappingTable    *walk.TableView
	mappingModel    *MappingTableModel
	logCheckBox     *walk.CheckBox
	logGroupBox     *walk.GroupBox
	logBottomBar    *walk.Composite
	logFile         *os.File

	proxyServer   *http.Server
	proxyRunning  bool
	proxyMutex    sync.Mutex
	certCache     *sync.Map
	caCert        *x509.Certificate
	caKey         *rsa.PrivateKey
	certInstalled bool

	httpClient = &http.Client{
		Timeout: 300 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
		},
	}
)

type MappingItem struct {
	Source string
	Target string
}

type MappingTableModel struct {
	walk.TableModelBase
	walk.SorterBase
	items   []MappingItem
	sortCol int
	sortAsc bool
}

func (m *MappingTableModel) RowCount() int {
	return len(m.items)
}

func (m *MappingTableModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.items) {
		return ""
	}
	item := m.items[row]
	switch col {
	case 0:
		return item.Source
	case 1:
		return item.Target
	}
	return ""
}

func (m *MappingTableModel) Sort(col int, order walk.SortOrder) error {
	m.sortCol = col
	m.sortAsc = order == walk.SortAscending
	sort.Slice(m.items, func(i, j int) bool {
		var less bool
		switch col {
		case 0:
			less = m.items[i].Source < m.items[j].Source
		case 1:
			less = m.items[i].Target < m.items[j].Target
		}
		if !m.sortAsc {
			less = !less
		}
		return less
	})
	m.PublishRowsReset()
	return nil
}

func (m *MappingTableModel) ResetRows() {
	m.items = nil
	if config.ModelMappings != nil {
		for source, target := range config.ModelMappings {
			m.items = append(m.items, MappingItem{Source: source, Target: target})
		}
		sort.Slice(m.items, func(i, j int) bool {
			return m.items[i].Source < m.items[j].Source
		})
	}
	m.PublishRowsReset()
}

// 检查单实例运行
func checkSingleInstance() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createMutex := kernel32.NewProc("CreateMutexW")

	mutexName, _ := syscall.UTF16PtrFromString("OpenAI_Anthropic_Proxy_Mutex")

	handle, _, err := createMutex.Call(
		0,
		0,
		uintptr(unsafe.Pointer(mutexName)),
	)

	if handle == 0 {
		return false
	}

	// ERROR_ALREADY_EXISTS = 183
	if err.(syscall.Errno) == 183 {
		return false
	}

	return true
}

var cleanupDone bool
var cleanupMutex sync.Mutex

func cleanupOnExit() {
	cleanupMutex.Lock()
	defer cleanupMutex.Unlock()

	if cleanupDone {
		return
	}

	if _, err := os.Stat(caCertFile); os.IsNotExist(err) {
		return
	}

	modifyHosts(false)
	uninstallCACert()
	if logFile != nil {
		logFile.Close()
		logFile = nil
	}
	cleanupDone = true
}

func setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		cleanupOnExit()
		if proxyRunning {
			stopProxy()
		}
		if notifyIcon != nil {
			notifyIcon.Dispose()
		}
		os.Exit(0)
	}()
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			cleanupOnExit()
			errMsg := fmt.Sprintf("程序崩溃: %v\n%s", r, debug.Stack())
			os.WriteFile("crash.log", []byte(errMsg), 0644)
			walk.MsgBox(nil, "程序错误", fmt.Sprintf("程序发生错误: %v\n\n详情已保存到 crash.log", r), walk.MsgBoxIconError)
		}
	}()

	defer cleanupOnExit()

	if !checkSingleInstance() {
		walk.MsgBox(nil, "提示", "程序已在运行中", walk.MsgBoxIconWarning)
		return
	}

	exePath, _ := os.Executable()
	workDir = filepath.Dir(exePath)
	os.Chdir(workDir)

	setupSignalHandler()

	// 加载配置
	loadConfig()
	updateLogMode()

	// 计算窗口居中位置
	windowWidth := 600
	windowHeight := 480
	if !config.ShowLog {
		windowHeight = 240
	}
	bounds := getWindowCenterBounds(windowWidth, windowHeight)

	// 创建主窗口
	var err error
	var icon *walk.Icon
	if _, statErr := os.Stat("icon.ico"); statErr == nil {
		icon, _ = walk.Resources.Icon("icon.ico")
	}
	if icon == nil {
		icon = walk.IconApplication()
	}

	err = MainWindow{
		AssignTo: &mainWindow,
		Title:    "OpenAI → Anthropic 协议转换代理",
		MinSize:  Size{Width: 600, Height: 240},
		Bounds:   bounds,
		Layout:   VBox{MarginsZero: false, Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}},
		Children: []Widget{
			TabWidget{
				Pages: []TabPage{
					{
						Title:  "基本设置",
						Layout: VBox{},
						Children: []Widget{
							GroupBox{
								Title:  "服务器设置",
								Layout: Grid{Columns: 2, Spacing: 10},
								Children: []Widget{
									Label{Text: "目标服务器:"},
									Composite{
										Layout: HBox{MarginsZero: true},
										Children: []Widget{
											ComboBox{
												AssignTo:      &targetURLCombo,
												Editable:      true,
												Model:         config.TargetURLHistory,
												Value:         config.TargetURL,
												ToolTipText:   "API 代理服务器地址",
												StretchFactor: 1,
											},
											PushButton{
												AssignTo:  &deleteURLButton,
												Text:      "✕",
												MaxSize:   Size{Width: 28},
												MinSize:   Size{Width: 28},
												OnClicked: onDeleteURLClicked,
											},
										},
									},
									Label{Text: "监听地址:"},
									LineEdit{
										AssignTo:    &listenAddrEdit,
										Text:        config.ListenAddr,
										ToolTipText: "本地监听地址 (默认 127.0.0.1)",
									},
									Label{Text: "转换协议:"},
									ComboBox{
										AssignTo:     &protocolCombo,
										Model:        protocolModes,
										CurrentIndex: config.ProtocolMode,
										ToolTipText:  "选择 API 协议转换模式",
									},
								},
							},
							Composite{
								Layout: HBox{},
								Children: []Widget{
									PushButton{
										AssignTo:  &proxyButton,
										Text:      "▶ 启动代理",
										OnClicked: onProxyButtonClicked,
									},
									PushButton{
										AssignTo:  &certButton,
										Text:      "📜 安装证书",
										OnClicked: onCertButtonClicked,
									},
									PushButton{
										AssignTo:  &testButton,
										Text:      "🔗 测试连接",
										OnClicked: onTestButtonClicked,
									},
									CheckBox{
										AssignTo: &logCheckBox,
										Text:     "显示日志",
										Checked:  config.ShowLog,
										OnCheckedChanged: func() {
											config.ShowLog = logCheckBox.Checked()
											if logGroupBox != nil {
												logGroupBox.SetVisible(config.ShowLog)
											}
											if logBottomBar != nil {
												logBottomBar.SetVisible(config.ShowLog)
											}
											bounds := mainWindow.Bounds()
											if config.ShowLog {
												bounds.Height = 480
											} else {
												bounds.Height = 240
											}
											mainWindow.SetBounds(bounds)
											updateLogMode()
											saveConfig()
										},
									},
									HSpacer{},
									Label{
										AssignTo: &statusLabel,
										Text:     "状态: 已停止",
									},
								},
							},
							GroupBox{
								AssignTo: &logGroupBox,
								Title:    "日志",
								Visible:  config.ShowLog,
								Layout:   VBox{},
								Children: []Widget{
									TextEdit{
										AssignTo:  &logTextEdit,
										ReadOnly:  true,
										VScroll:   true,
										MaxLength: 100000,
									},
								},
							},
							Composite{
								AssignTo: &logBottomBar,
								Visible:  config.ShowLog,
								Layout:   HBox{},
								Children: []Widget{
									PushButton{
										Text: "清空日志",
										OnClicked: func() {
											logTextEdit.SetText("")
										},
									},
									HSpacer{},
								},
							},
						},
					},
					{
						Title:  "模型映射",
						Layout: VBox{},
						Children: []Widget{
							Label{Text: "配置模型名称映射规则（请求中的模型名称将被自动替换）:"},
							TableView{
								AssignTo:         &mappingTable,
								AlternatingRowBG: true,
								ColumnsOrderable: true,
								Columns: []TableViewColumn{
									{Title: "源模型名称", Width: 280},
									{Title: "目标模型名称", Width: 280},
								},
								Model: func() *MappingTableModel {
									mappingModel = &MappingTableModel{}
									mappingModel.ResetRows()
									return mappingModel
								}(),
							},
						},
					},
				},
			},
		},
	}.Create()

	if err != nil {
		fmt.Printf("创建窗口失败: %v\n", err)
		return
	}

	if icon != nil {
		mainWindow.SetIcon(icon)
	}

	mappingMenu, _ := walk.NewMenu()
	addAction := walk.NewAction()
	addAction.SetText("添加映射")
	addAction.Triggered().Attach(func() { onAddMappingClicked() })
	mappingMenu.Actions().Add(addAction)

	editAction := walk.NewAction()
	editAction.SetText("编辑映射")
	editAction.Triggered().Attach(func() { onEditMappingClicked() })
	mappingMenu.Actions().Add(editAction)

	mappingMenu.Actions().Add(walk.NewSeparatorAction())

	deleteAction := walk.NewAction()
	deleteAction.SetText("删除映射")
	deleteAction.Triggered().Attach(func() { onDeleteMappingClicked() })
	mappingMenu.Actions().Add(deleteAction)

	mappingTable.SetContextMenu(mappingMenu)

	// 创建托盘图标
	createTrayIcon(icon)

	// 设置窗口关闭行为
	mainWindow.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if reason == walk.CloseReasonUser {
			*canceled = true
			mainWindow.Hide()
		} else {
			cleanupOnExit()
			stopProxy()
			if notifyIcon != nil {
				notifyIcon.Dispose()
			}
		}
	})

	user32dll := syscall.NewLazyDLL("user32.dll")
	isIconic := user32dll.NewProc("IsIconic")
	showWindowProc := user32dll.NewProc("ShowWindow")
	mainWindow.SizeChanged().Attach(func() {
		ret, _, _ := isIconic.Call(uintptr(mainWindow.Handle()))
		if ret != 0 {
			showWindowProc.Call(uintptr(mainWindow.Handle()), 9)
			mainWindow.Hide()
		}
	})

	// 检测证书状态
	checkCertStatus()

	// 初始化日志
	appendLog("程序已启动")
	appendLog(fmt.Sprintf("目标服务器: %s", config.TargetURL))
	if certInstalled {
		appendLog("✅ 证书已安装，可以启动代理")
	} else {
		appendLog("请先安装证书，然后启动代理")
	}

	// 运行主窗口
	mainWindow.Run()

	// 清理
	if notifyIcon != nil {
		notifyIcon.Dispose()
	}
}

func createTrayIcon(icon *walk.Icon) {
	var err error
	notifyIcon, err = walk.NewNotifyIcon(mainWindow)
	if err != nil {
		appendLog(fmt.Sprintf("创建托盘图标失败: %v", err))
		return
	}

	if icon != nil {
		notifyIcon.SetIcon(icon)
	}
	notifyIcon.SetToolTip("OpenAI → Anthropic 代理")

	// 双击托盘图标显示窗口
	notifyIcon.MouseUp().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			mainWindow.Show()
			mainWindow.SetFocus()
		}
	})

	// 托盘右键菜单
	showAction := walk.NewAction()
	showAction.SetText("显示窗口")
	showAction.Triggered().Attach(func() {
		mainWindow.Show()
		mainWindow.SetFocus()
	})
	notifyIcon.ContextMenu().Actions().Add(showAction)

	notifyIcon.ContextMenu().Actions().Add(walk.NewSeparatorAction())

	exitAction := walk.NewAction()
	exitAction.SetText("退出")
	exitAction.Triggered().Attach(func() {
		cleanupOnExit()
		stopProxy()
		notifyIcon.Dispose()
		mainWindow.Close()
		os.Exit(0)
	})
	notifyIcon.ContextMenu().Actions().Add(exitAction)

	notifyIcon.SetVisible(true)
}

func loadConfig() {
	config = Config{
		TargetURL:    "http://ai.32l.cn",
		ListenAddr:   "127.0.0.1",
		ProtocolMode: ModeAnthropic,
		ShowLog:      true,
		ModelMappings: map[string]string{
			"claude-sonnet-4-5-20250929": "claude-sonnet-4-5-thinking",
			"claude-opus-4-1-20250805":   "claude-opus-4-5-thinking",
		},
	}

	data, err := os.ReadFile(configFile)
	if err == nil {
		json.Unmarshal(data, &config)
	}

	// 如果映射规则为空，填充默认规则
	if config.ModelMappings == nil || len(config.ModelMappings) == 0 {
		config.ModelMappings = map[string]string{
			"claude-sonnet-4-5-20250929": "claude-sonnet-4-5-thinking",
			"claude-opus-4-1-20250805":   "claude-opus-4-5-thinking",
		}
	}

	if config.TargetURLHistory == nil {
		config.TargetURLHistory = []string{}
	}
}

func getWindowCenterBounds(width, height int) Rectangle {
	// 获取屏幕尺寸
	user32 := syscall.NewLazyDLL("user32.dll")
	getSystemMetrics := user32.NewProc("GetSystemMetrics")

	// SM_CXSCREEN = 0, SM_CYSCREEN = 1
	screenWidth, _, _ := getSystemMetrics.Call(0)
	screenHeight, _, _ := getSystemMetrics.Call(1)

	// 计算居中位置
	x := (int(screenWidth) - width) / 2
	y := (int(screenHeight) - height) / 2

	return Rectangle{
		X:      x,
		Y:      y,
		Width:  width,
		Height: height,
	}
}

func checkCertStatus() {
	// 检查证书文件是否存在
	if _, err := os.Stat(caCertFile); err == nil {
		certInstalled = true
		certButton.SetText("🗑️ 卸载证书")
	} else {
		certInstalled = false
		certButton.SetText("📜 安装证书")
	}
}

func saveConfig() {
	config.TargetURL = targetURLCombo.Text()
	config.ListenAddr = listenAddrEdit.Text()
	config.ProtocolMode = protocolCombo.CurrentIndex()

	url := strings.TrimSpace(config.TargetURL)
	if url != "" {
		found := false
		for _, h := range config.TargetURLHistory {
			if h == url {
				found = true
				break
			}
		}
		if !found {
			config.TargetURLHistory = append([]string{url}, config.TargetURLHistory...)
			refreshTargetURLHistory()
		}
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configFile, data, 0644)
}

func refreshTargetURLHistory() {
	if targetURLCombo == nil {
		return
	}
	currentText := targetURLCombo.Text()
	targetURLCombo.SetModel(config.TargetURLHistory)
	targetURLCombo.SetText(currentText)
}

func removeTargetURLHistory(index int) {
	if index < 0 || index >= len(config.TargetURLHistory) {
		return
	}
	removed := config.TargetURLHistory[index]
	config.TargetURLHistory = append(config.TargetURLHistory[:index], config.TargetURLHistory[index+1:]...)
	refreshTargetURLHistory()
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configFile, data, 0644)
	appendLog(fmt.Sprintf("🗑️ 已删除历史记录: %s", removed))
}

func onDeleteURLClicked() {
	currentText := strings.TrimSpace(targetURLCombo.Text())
	if currentText == "" {
		return
	}
	idx := -1
	for i, h := range config.TargetURLHistory {
		if h == currentText {
			idx = i
			break
		}
	}
	if idx >= 0 {
		config.TargetURLHistory = append(config.TargetURLHistory[:idx], config.TargetURLHistory[idx+1:]...)
	}
	if len(config.TargetURLHistory) > 0 {
		targetURLCombo.SetModel(config.TargetURLHistory)
		targetURLCombo.SetText(config.TargetURLHistory[0])
	} else {
		targetURLCombo.SetModel([]string{})
		targetURLCombo.SetText("")
	}
	config.TargetURL = targetURLCombo.Text()
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configFile, data, 0644)
	appendLog(fmt.Sprintf("🗑️ 已删除历史记录: %s", currentText))
}

func updateLogMode() {
	if config.ShowLog {
		if logFile != nil {
			logFile.Close()
			logFile = nil
		}
	} else {
		if logFile == nil {
			exePath, _ := os.Executable()
			logName := strings.TrimSuffix(filepath.Base(exePath), filepath.Ext(exePath)) + ".log"
			logPath := filepath.Join(filepath.Dir(exePath), logName)
			f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err == nil {
				logFile = f
			}
		}
	}
}

func appendLog(msg string) {
	msg = strings.ReplaceAll(msg, "\x00", "")
	timestamp := time.Now().Format("15:04:05")
	logLine := fmt.Sprintf("[%s] %s\r\n", timestamp, msg)

	if config.ShowLog && logTextEdit != nil {
		mainWindow.Synchronize(func() {
			logTextEdit.AppendText(logLine)
		})
	}

	if logFile != nil {
		logFile.WriteString(logLine)
	}
}

func onTestButtonClicked() {
	targetURL := targetURLCombo.Text()
	if targetURL == "" {
		appendLog("❌ 请输入目标服务器地址")
		return
	}

	testButton.SetEnabled(false)
	testButton.SetText("测试中...")

	go func() {
		defer mainWindow.Synchronize(func() {
			testButton.SetEnabled(true)
			testButton.SetText("🔗 测试连接")
		})

		appendLog(fmt.Sprintf("🔗 测试连接: %s", targetURL))

		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}

		testURL := strings.TrimSuffix(targetURL, "/")
		resp, err := client.Get(testURL)
		if err != nil {
			appendLog(fmt.Sprintf("❌ 连接失败: %v", err))
			return
		}
		defer resp.Body.Close()

		appendLog(fmt.Sprintf("✅ 连接成功! 状态码: %d", resp.StatusCode))
	}()
}

func onAddMappingClicked() {
	var sourceEdit, targetEdit *walk.LineEdit
	var dlg *walk.Dialog

	Dialog{
		AssignTo:      &dlg,
		Title:         "添加模型映射",
		DefaultButton: nil,
		CancelButton:  nil,
		MinSize:       Size{Width: 400, Height: 150},
		Layout:        VBox{},
		Children: []Widget{
			Composite{
				Layout: Grid{Columns: 2, Spacing: 10},
				Children: []Widget{
					Label{Text: "源模型名称:"},
					LineEdit{AssignTo: &sourceEdit},
					Label{Text: "目标模型名称:"},
					LineEdit{AssignTo: &targetEdit},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						Text: "确定",
						OnClicked: func() {
							source := sourceEdit.Text()
							target := targetEdit.Text()
							if source == "" || target == "" {
								walk.MsgBox(dlg, "错误", "请输入源模型名称和目标模型名称", walk.MsgBoxIconError)
								return
							}
							if config.ModelMappings == nil {
								config.ModelMappings = make(map[string]string)
							}
							config.ModelMappings[source] = target
							saveConfig()
							mappingModel.ResetRows()
							appendLog(fmt.Sprintf("✅ 已添加模型映射: %s -> %s", source, target))
							dlg.Accept()
						},
					},
					PushButton{
						Text: "取消",
						OnClicked: func() {
							dlg.Cancel()
						},
					},
				},
			},
		},
	}.Run(mainWindow)
}

func onEditMappingClicked() {
	idx := mappingTable.CurrentIndex()
	if idx < 0 || idx >= len(mappingModel.items) {
		walk.MsgBox(mainWindow, "提示", "请先选择要编辑的映射", walk.MsgBoxIconInformation)
		return
	}

	item := mappingModel.items[idx]
	var sourceEdit, targetEdit *walk.LineEdit
	var dlg *walk.Dialog

	Dialog{
		AssignTo:      &dlg,
		Title:         "编辑模型映射",
		DefaultButton: nil,
		CancelButton:  nil,
		MinSize:       Size{Width: 400, Height: 150},
		Layout:        VBox{},
		Children: []Widget{
			Composite{
				Layout: Grid{Columns: 2, Spacing: 10},
				Children: []Widget{
					Label{Text: "源模型名称:"},
					LineEdit{AssignTo: &sourceEdit, Text: item.Source},
					Label{Text: "目标模型名称:"},
					LineEdit{AssignTo: &targetEdit, Text: item.Target},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						Text: "确定",
						OnClicked: func() {
							source := sourceEdit.Text()
							target := targetEdit.Text()
							if source == "" || target == "" {
								walk.MsgBox(dlg, "错误", "请输入源模型名称和目标模型名称", walk.MsgBoxIconError)
								return
							}
							delete(config.ModelMappings, item.Source)
							config.ModelMappings[source] = target
							saveConfig()
							mappingModel.ResetRows()
							appendLog(fmt.Sprintf("✅ 已更新模型映射: %s -> %s", source, target))
							dlg.Accept()
						},
					},
					PushButton{
						Text: "取消",
						OnClicked: func() {
							dlg.Cancel()
						},
					},
				},
			},
		},
	}.Run(mainWindow)
}

func onDeleteMappingClicked() {
	idx := mappingTable.CurrentIndex()
	if idx < 0 || idx >= len(mappingModel.items) {
		walk.MsgBox(mainWindow, "提示", "请先选择要删除的映射", walk.MsgBoxIconInformation)
		return
	}

	item := mappingModel.items[idx]
	if walk.MsgBox(mainWindow, "确认删除", fmt.Sprintf("确定要删除映射 \"%s\" 吗?", item.Source), walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes {
		delete(config.ModelMappings, item.Source)
		saveConfig()
		mappingModel.ResetRows()
		appendLog(fmt.Sprintf("🗑️ 已删除模型映射: %s", item.Source))
	}
}

func onProxyButtonClicked() {
	if proxyRunning {
		// 停止代理
		stopProxy()
	} else {
		// 启动代理
		startProxy()
	}
}

func startProxy() {
	proxyMutex.Lock()
	if proxyRunning {
		proxyMutex.Unlock()
		return
	}
	proxyMutex.Unlock()

	saveConfig()

	if _, err := os.Stat(caCertFile); os.IsNotExist(err) {
		appendLog("📜 证书不存在，自动生成...")
		if err := generateCertificates(); err != nil {
			appendLog(fmt.Sprintf("❌ 生成证书失败: %v", err))
			return
		}
		appendLog("✅ 证书生成完成")
	}

	appendLog("📝 添加 hosts 劫持...")
	if err := modifyHosts(true); err != nil {
		appendLog(fmt.Sprintf("❌ 修改 hosts 失败: %v", err))
		appendLog("请以管理员身份运行程序")
		return
	}
	appendLog("✅ hosts 已更新")

	appendLog("🔐 安装 CA 证书...")
	if err := installCACert(); err != nil {
		appendLog(fmt.Sprintf("❌ 安装证书失败: %v", err))
		appendLog("请以管理员身份运行程序")
		modifyHosts(false)
		return
	}
	appendLog("✅ CA 证书已安装")

	certInstalled = true
	mainWindow.Synchronize(func() {
		certButton.SetText("🗑️ 卸载证书")
	})

	if err := loadCertificates(); err != nil {
		appendLog(fmt.Sprintf("❌ 加载证书失败: %v", err))
		return
	}

	go startProxyServer()
}

func stopProxy() {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	if !proxyRunning {
		return
	}

	if proxyServer != nil {
		proxyServer.Close()
		proxyServer = nil
	}

	proxyRunning = false

	mainWindow.Synchronize(func() {
		proxyButton.SetText("▶ 启动代理")
		statusLabel.SetText("状态: 已停止")
	})

	appendLog("⏹️ 代理已停止")
}

func onCertButtonClicked() {
	if certInstalled {
		// 卸载证书
		uninstallCert()
	} else {
		// 安装证书
		installCert()
	}
}

func installCert() {
	appendLog("🔧 开始安装...")

	go func() {
		// 生成证书
		if _, err := os.Stat(caCertFile); os.IsNotExist(err) {
			appendLog("📜 生成证书...")
			if err := generateCertificates(); err != nil {
				appendLog(fmt.Sprintf("❌ 生成证书失败: %v", err))
				return
			}
			appendLog("✅ 证书生成完成")
		}

		// 修改 hosts
		appendLog("📝 修改 hosts 文件...")
		if err := modifyHosts(true); err != nil {
			appendLog(fmt.Sprintf("❌ 修改 hosts 失败: %v", err))
			appendLog("请以管理员身份运行程序")
			return
		}
		appendLog("✅ hosts 文件已更新")

		// 安装证书
		appendLog("🔐 安装 CA 证书...")
		if err := installCACert(); err != nil {
			appendLog(fmt.Sprintf("❌ 安装证书失败: %v", err))
			appendLog("请以管理员身份运行程序")
			return
		}
		appendLog("✅ CA 证书已安装")

		certInstalled = true
		mainWindow.Synchronize(func() {
			certButton.SetText("🗑️ 卸载证书")
		})

		appendLog("🎉 安装完成！")
		appendLog("请配置 v2rayN: domain:api.openai.com → direct")
	}()
}

func uninstallCert() {
	appendLog("🔧 开始卸载...")

	go func() {
		// 恢复 hosts
		appendLog("📝 恢复 hosts 文件...")
		if err := modifyHosts(false); err != nil {
			appendLog(fmt.Sprintf("⚠️ 恢复 hosts 失败: %v", err))
		} else {
			appendLog("✅ hosts 文件已恢复")
		}

		// 移除证书
		appendLog("🔐 移除 CA 证书...")
		uninstallCACert()
		appendLog("✅ CA 证书已移除")

		certInstalled = false
		mainWindow.Synchronize(func() {
			certButton.SetText("📜 安装证书")
		})

		appendLog("🎉 卸载完成！")
	}()
}

func loadCertificates() error {
	certCache = &sync.Map{}

	// 加载 CA
	caCertPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return err
	}
	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return err
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	caKeyBlock, _ := pem.Decode(caKeyPEM)

	var parseErr error
	caCert, parseErr = x509.ParseCertificate(caCertBlock.Bytes)
	if parseErr != nil {
		return parseErr
	}

	caKey, parseErr = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if parseErr != nil {
		return parseErr
	}

	for _, domain := range proxyDomains {
		safeName := strings.ReplaceAll(domain, ".", "_")
		certFile := fmt.Sprintf("%s/cert_%s.crt", certsDir, safeName)
		keyFile := fmt.Sprintf("%s/cert_%s.key", certsDir, safeName)

		if _, err := os.Stat(certFile); err == nil {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err == nil {
				certCache.Store(domain, &cert)
				appendLog(fmt.Sprintf("📜 已加载证书: %s", domain))
			}
		} else {
			appendLog(fmt.Sprintf("📜 生成证书: %s", domain))
			if err := generateDomainCert(domain, caCert, caKey); err != nil {
				appendLog(fmt.Sprintf("❌ 生成证书失败: %s - %v", domain, err))
				continue
			}
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err == nil {
				certCache.Store(domain, &cert)
			}
		}
	}

	return nil
}

func startProxyServer() {
	proxyMutex.Lock()
	proxyRunning = true
	proxyMutex.Unlock()

	mainWindow.Synchronize(func() {
		proxyButton.SetText("■ 停止代理")
		statusLabel.SetText("状态: 运行中")
	})

	appendLog(fmt.Sprintf("🚀 启动代理服务器 %s:443", config.ListenAddr))
	appendLog(fmt.Sprintf("📡 目标服务器: %s", config.TargetURL))

	if certInstalled {
		appendLog("🔐 检查并更新系统 CA 证书...")
		installCACert()
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			serverName := hello.ServerName
			if serverName == "" {
				serverName = proxyDomains[0]
			}
			if cached, ok := certCache.Load(serverName); ok {
				return cached.(*tls.Certificate), nil
			}
			return getOrCreateCert(serverName)
		},
	}

	handler := http.HandlerFunc(handleRequest)

	proxyServer = &http.Server{
		Addr:         fmt.Sprintf("%s:443", config.ListenAddr),
		Handler:      handler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	listener, err := net.Listen("tcp", proxyServer.Addr)
	if err != nil {
		appendLog(fmt.Sprintf("❌ 无法监听端口 443: %v", err))
		proxyMutex.Lock()
		proxyRunning = false
		proxyMutex.Unlock()
		mainWindow.Synchronize(func() {
			proxyButton.SetText("▶ 启动代理")
			statusLabel.SetText("状态: 已停止")
		})
		return
	}

	tlsListener := tls.NewListener(listener, proxyServer.TLSConfig)

	appendLog("✅ 代理服务器已启动")

	if err := proxyServer.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		appendLog(fmt.Sprintf("❌ 服务器错误: %v", err))
	}

	proxyMutex.Lock()
	proxyRunning = false
	proxyMutex.Unlock()
}

func maskAPIKey(key string) string {
	if len(key) <= 10 {
		return "***"
	}
	return key[:10] + "***"
}

func normalizeRequestPath(path string) string {
	if config.ProtocolMode == ModeOpenAI {
		return path
	}
	if strings.HasPrefix(path, "/v1beta/openai/") {
		newPath := strings.Replace(path, "/v1beta/openai/", "/v1/", 1)
		appendLog(fmt.Sprintf("🔄 路径转换: %s -> %s", path, newPath))
		return newPath
	}
	if strings.HasPrefix(path, "/api/v1/") {
		newPath := strings.TrimPrefix(path, "/api")
		appendLog(fmt.Sprintf("🔄 路径转换: %s -> %s", path, newPath))
		return newPath
	}
	return path
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	queryStr := ""
	if r.URL.RawQuery != "" {
		queryStr = "?" + r.URL.RawQuery
	}
	appendLog(fmt.Sprintf("➡️ %s %s%s (Host: %s, Auth=%s)", r.Method, r.URL.Path, queryStr, r.Host, maskAPIKey(r.Header.Get("Authorization"))))

	path := normalizeRequestPath(r.URL.Path)

	if r.Method == "POST" {
		appendLog(fmt.Sprintf("🔍 路由匹配: path=%s, 原始path=%s, 协议模式=%d", path, r.URL.Path, config.ProtocolMode))
		switch path {
		case "/v1/chat/completions", "/v1/completions", "/v1/responses":
			handleChatCompletion(w, r, path)
			return
		case "/v1/messages":
			handleAnthropicIncoming(w, r)
			return
		}
		if strings.Contains(path, "/messages") {
			appendLog(fmt.Sprintf("⚠️ 包含 /messages 但未精确匹配: %s", path))
			handleAnthropicIncoming(w, r)
			return
		}
	}

	handlePassthrough(w, r)
}

func handlePassthrough(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	path := normalizeRequestPath(r.URL.Path)
	targetURL := config.TargetURL

	if r.Method == "POST" && strings.Contains(path, "/messages") {
		var reqBody map[string]interface{}
		if err := json.Unmarshal(body, &reqBody); err == nil {
			if model, ok := reqBody["model"].(string); ok {
				originalModel := model
				if strings.Contains(model, "/") {
					parts := strings.SplitN(model, "/", 2)
					if len(parts) == 2 {
						model = parts[1]
					}
				}
				stream, _ := reqBody["stream"].(bool)
				maxTokens, _ := reqBody["max_tokens"].(float64)
				appendLog(fmt.Sprintf("📋 原始请求参数: model=%s, stream=%v, max_tokens=%v", originalModel, stream, int(maxTokens)))
				mapped := false
				if config.ModelMappings != nil {
					if mappedModel, exists := config.ModelMappings[model]; exists {
						appendLog(fmt.Sprintf("🔄 模型映射: %s -> %s", originalModel, mappedModel))
						reqBody["model"] = mappedModel
						newBody, _ := json.Marshal(reqBody)
						body = newBody
						mapped = true
					}
				}
				if !mapped {
					appendLog(fmt.Sprintf("⚠️ 未匹配映射规则, 实际发送模型: %s", model))
				}
			}
		}
	}

	targetURL = targetURL + path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	appendLog(fmt.Sprintf("📤 透传请求: %s %s", r.Method, targetURL))

	req, err := http.NewRequest(r.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		appendLog(fmt.Sprintf("❌ 创建透传请求失败: %v", err))
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	for key, values := range r.Header {
		if strings.EqualFold(key, "Accept-Encoding") {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	if req.Header.Get("Authorization") == "" {
		if apiKey := req.Header.Get("X-Api-Key"); apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
			appendLog("🔑 透传: 已转换 x-api-key → Authorization")
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		appendLog(fmt.Sprintf("❌ 透传请求失败: %v", err))
		http.Error(w, "Failed to reach target server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	isStreamResponse := strings.Contains(contentType, "text/event-stream")

	if isStreamResponse {
		flusher, ok := w.(http.Flusher)
		if !ok {
			appendLog("❌ 不支持流式响应")
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}

		for key, values := range resp.Header {
			if strings.EqualFold(key, "Content-Encoding") || strings.EqualFold(key, "Content-Length") {
				continue
			}
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		flusher.Flush()

		appendLog(fmt.Sprintf("📤 透传流式响应: %d", resp.StatusCode))

		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				flusher.Flush()
			}
			if err != nil {
				if err != io.EOF {
					appendLog(fmt.Sprintf("❌ 读取流失败: %v", err))
				}
				break
			}
		}

		appendLog("⬅️ 透传流式响应完成")
		return
	}

	respBody, _ := io.ReadAll(resp.Body)

	if strings.Contains(r.URL.Path, "/models") && resp.StatusCode == 200 {
		isAnthropicClient := strings.Contains(r.Host, "anthropic") || r.Header.Get("x-api-key") != ""
		if isAnthropicClient {
			respBody = convertToAnthropicModelFormat(respBody)
			appendLog("🔄 已转换模型列表为 Anthropic 格式 (客户端检测)")
		} else {
			switch config.ProtocolMode {
			case ModeAnthropic:
				respBody = convertToAnthropicModelFormat(respBody)
				appendLog("🔄 已转换模型列表为 Anthropic 格式")
			case ModeOpenAIConvert:
				respBody = convertGeminiToOpenAIModelFormat(respBody)
				appendLog("🔄 已转换模型列表为 OpenAI 格式")
			default:
				respBody = injectMappingModelsToOpenAI(respBody)
			}
		}
	}

	if resp.StatusCode != 200 {
		appendLog(fmt.Sprintf("📥 透传响应: %d (%d bytes): %s", resp.StatusCode, len(respBody), string(respBody[:min(200, len(respBody))])))
	} else {
		previewLen := min(500, len(respBody))
		appendLog(fmt.Sprintf("📥 透传响应: %d (%d bytes) 内容预览: %s", resp.StatusCode, len(respBody), string(respBody[:previewLen])))
		if logFile != nil && len(respBody) > previewLen {
			timestamp := time.Now().Format("15:04:05")
			logFile.WriteString(fmt.Sprintf("[%s] 📥 完整响应: %s\r\n", timestamp, string(respBody)))
		}
	}

	for key, values := range resp.Header {
		if strings.ToLower(key) == "content-length" {
			continue
		}
		if strings.ToLower(key) == "content-encoding" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBody)))

	appendLog(fmt.Sprintf("📋 响应头: Content-Type=%s, Content-Length=%d", resp.Header.Get("Content-Type"), len(respBody)))

	w.WriteHeader(resp.StatusCode)
	n, err := w.Write(respBody)
	if err != nil {
		appendLog(fmt.Sprintf("❌ 写入响应失败: %v", err))
	} else {
		appendLog(fmt.Sprintf("✅ 已写入 %d bytes 到客户端", n))
	}
}

func convertToAnthropicModelFormat(respBody []byte) []byte {
	var modelResp struct {
		Data []struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Created int64  `json:"created"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}

	if err := json.Unmarshal(respBody, &modelResp); err != nil {
		return respBody
	}

	type AnthropicModel struct {
		Type        string `json:"type"`
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
		CreatedAt   string `json:"created_at"`
	}

	var anthropicModels []AnthropicModel
	for _, m := range modelResp.Data {
		if strings.HasPrefix(m.ID, "claude") || strings.Contains(m.ID, "claude") {
			displayName := strings.ReplaceAll(m.ID, "-", " ")
			displayName = toTitleCase(displayName)
			createdAt := time.Unix(m.Created, 0).Format(time.RFC3339)

			anthropicModels = append(anthropicModels, AnthropicModel{
				Type:        "model",
				ID:          m.ID,
				DisplayName: displayName,
				CreatedAt:   createdAt,
			})
		}
	}

	if len(anthropicModels) == 0 {
		return respBody
	}

	// 从映射表自动注入源模型名称到模型列表
	existingIDs := make(map[string]bool)
	for _, m := range anthropicModels {
		existingIDs[m.ID] = true
	}

	if config.ModelMappings != nil {
		for source := range config.ModelMappings {
			if !existingIDs[source] {
				displayName := strings.ReplaceAll(source, "-", " ")
				displayName = toTitleCase(displayName)
				anthropicModels = append(anthropicModels, AnthropicModel{
					Type:        "model",
					ID:          source,
					DisplayName: displayName,
					CreatedAt:   time.Now().Format(time.RFC3339),
				})
				existingIDs[source] = true
			}
		}
	}

	var modelIDs []string
	for _, m := range anthropicModels {
		modelIDs = append(modelIDs, m.ID)
	}
	appendLog(fmt.Sprintf("📋 Anthropic 模型列表 (%d 个): %v", len(anthropicModels), modelIDs))

	response := map[string]interface{}{
		"data":     anthropicModels,
		"has_more": false,
		"first_id": anthropicModels[0].ID,
		"last_id":  anthropicModels[len(anthropicModels)-1].ID,
	}

	newBody, err := json.Marshal(response)
	if err != nil {
		return respBody
	}

	return newBody
}

func convertGeminiToOpenAIModelFormat(respBody []byte) []byte {
	type OpenAIModel struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		OwnedBy string `json:"owned_by"`
	}

	var models []OpenAIModel

	var geminiResp struct {
		Models []struct {
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"models"`
	}
	if err := json.Unmarshal(respBody, &geminiResp); err == nil && len(geminiResp.Models) > 0 {
		for _, m := range geminiResp.Models {
			modelID := m.DisplayName
			if modelID == "" {
				modelID = strings.TrimPrefix(m.Name, "models/")
			}
			models = append(models, OpenAIModel{
				ID:      modelID,
				Object:  "model",
				Created: time.Now().Unix(),
				OwnedBy: "google",
			})
		}
	} else {
		var openaiResp struct {
			Data []OpenAIModel `json:"data"`
		}
		if err := json.Unmarshal(respBody, &openaiResp); err == nil && len(openaiResp.Data) > 0 {
			models = openaiResp.Data
		}
	}

	existingIDs := make(map[string]bool)
	for _, m := range models {
		existingIDs[m.ID] = true
	}
	if config.ModelMappings != nil {
		for source := range config.ModelMappings {
			if !existingIDs[source] {
				models = append(models, OpenAIModel{
					ID:      source,
					Object:  "model",
					Created: time.Now().Unix(),
					OwnedBy: "mapped",
				})
				existingIDs[source] = true
			}
		}
	}

	if len(models) == 0 {
		return respBody
	}

	var modelIDs []string
	for _, m := range models {
		modelIDs = append(modelIDs, m.ID)
	}
	appendLog(fmt.Sprintf("📋 OpenAI转换 模型列表 (%d 个): %v", len(models), modelIDs))

	response := map[string]interface{}{
		"object": "list",
		"data":   models,
	}

	newBody, err := json.Marshal(response)
	if err != nil {
		return respBody
	}

	return newBody
}

func injectMappingModelsToOpenAI(respBody []byte) []byte {
	if config.ModelMappings == nil || len(config.ModelMappings) == 0 {
		return respBody
	}

	var modelResp struct {
		Object string `json:"object"`
		Data   []struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Created int64  `json:"created"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}

	if err := json.Unmarshal(respBody, &modelResp); err != nil {
		return respBody
	}

	existingIDs := make(map[string]bool)
	for _, m := range modelResp.Data {
		existingIDs[m.ID] = true
	}

	injected := 0
	for source := range config.ModelMappings {
		if !existingIDs[source] {
			modelResp.Data = append(modelResp.Data, struct {
				ID      string `json:"id"`
				Object  string `json:"object"`
				Created int64  `json:"created"`
				OwnedBy string `json:"owned_by"`
			}{
				ID:      source,
				Object:  "model",
				Created: time.Now().Unix(),
				OwnedBy: "mapped",
			})
			existingIDs[source] = true
			injected++
		}
	}

	if injected > 0 {
		appendLog(fmt.Sprintf("🔄 已注入 %d 个映射模型到 OpenAI 模型列表", injected))
	}

	newBody, err := json.Marshal(modelResp)
	if err != nil {
		return respBody
	}
	return newBody
}

func handleChatCompletion(w http.ResponseWriter, r *http.Request, apiPath string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		appendLog(fmt.Sprintf("❌ 读取请求失败: %v", err))
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var openaiReq OpenAIRequest
	if err := json.Unmarshal(body, &openaiReq); err != nil {
		appendLog(fmt.Sprintf("❌ 解析请求失败: %v", err))
		http.Error(w, "Failed to parse request", http.StatusBadRequest)
		return
	}

	originalModel := openaiReq.Model
	if strings.Contains(openaiReq.Model, "/") {
		parts := strings.SplitN(openaiReq.Model, "/", 2)
		if len(parts) == 2 {
			openaiReq.Model = parts[1]
		}
	}

	// 模型名称映射
	if config.ModelMappings != nil {
		if mappedModel, exists := config.ModelMappings[openaiReq.Model]; exists {
			appendLog(fmt.Sprintf("🔄 模型映射: %s -> %s", openaiReq.Model, mappedModel))
			openaiReq.Model = mappedModel
		}
	}

	if originalModel != openaiReq.Model {
		appendLog(fmt.Sprintf("📥 请求: model=%s (原始: %s), stream=%v, messages=%d", openaiReq.Model, originalModel, openaiReq.Stream, len(openaiReq.Messages)))
	} else {
		appendLog(fmt.Sprintf("📥 请求: model=%s, stream=%v, messages=%d", openaiReq.Model, openaiReq.Stream, len(openaiReq.Messages)))
	}

	openaiReq.Stream = true

	// 根据协议模式选择不同的处理
	switch config.ProtocolMode {
	case ModeOpenAI:
		handleOpenAIDirect(w, r, body, openaiReq, apiPath)
	case ModeAnthropic:
		handleAnthropicConvert(w, r, openaiReq)
	case ModeOpenAIConvert:
		handleOpenAIConvert(w, r, openaiReq, apiPath)
	default:
		handleAnthropicConvert(w, r, openaiReq)
	}
}

// OpenAI 直连模式
func handleOpenAIDirect(w http.ResponseWriter, r *http.Request, body []byte, openaiReq OpenAIRequest, apiPath string) {
	appendLog(fmt.Sprintf("🔄 OpenAI 直连: model=%s, stream=%v", openaiReq.Model, openaiReq.Stream))

	openaiBody, err := json.Marshal(openaiReq)
	if err != nil {
		appendLog(fmt.Sprintf("❌ 序列化请求失败: %v", err))
		http.Error(w, "Failed to marshal request", http.StatusInternalServerError)
		return
	}

	targetURL := config.TargetURL + apiPath
	appendLog(fmt.Sprintf("📤 目标: %s", targetURL))

	req, err := http.NewRequest("POST", targetURL, bytes.NewReader(openaiBody))
	if err != nil {
		appendLog(fmt.Sprintf("❌ 创建请求失败: %v", err))
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		appendLog(fmt.Sprintf("❌ 请求目标服务器失败: %v", err))
		http.Error(w, "Failed to reach target server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	appendLog(fmt.Sprintf("📥 响应状态: %d", resp.StatusCode))

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		appendLog(fmt.Sprintf("❌ 错误响应: %s", string(respBody[:min(500, len(respBody))])))
		for k, v := range resp.Header {
			if strings.EqualFold(k, "Content-Encoding") || strings.EqualFold(k, "Content-Length") {
				continue
			}
			w.Header()[k] = v
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBody)))
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	handleOpenAIStreamResponse(w, resp, openaiReq.Model)
}

// OpenAI 转换模式 - 将请求转换为标准 OpenAI 格式发送
func handleOpenAIConvert(w http.ResponseWriter, r *http.Request, openaiReq OpenAIRequest, apiPath string) {
	defer func() {
		if rec := recover(); rec != nil {
			appendLog(fmt.Sprintf("❌ OpenAI 转换 panic: %v", rec))
		}
	}()

	appendLog(fmt.Sprintf("🔄 OpenAI 转换: model=%s, stream=%v", openaiReq.Model, openaiReq.Stream))

	openaiBody, err := json.Marshal(openaiReq)
	if err != nil {
		appendLog(fmt.Sprintf("❌ 序列化请求失败: %v", err))
		http.Error(w, "Failed to marshal request", http.StatusInternalServerError)
		return
	}

	targetURL := config.TargetURL + apiPath
	appendLog(fmt.Sprintf("📤 目标: %s", targetURL))

	req, err := http.NewRequest("POST", targetURL, nil)
	if err != nil {
		appendLog(fmt.Sprintf("❌ 创建请求失败: %v", err))
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := doRequestWithRetry(req, openaiBody, 3)
	if err != nil {
		appendLog(fmt.Sprintf("❌ 请求失败: %v", err))
		http.Error(w, "Failed to reach target server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	handleOpenAIStreamResponse(w, resp, openaiReq.Model)
}

// 处理 OpenAI 流式响应
func handleOpenAIStreamResponse(w http.ResponseWriter, resp *http.Response, originalModel string) {
	defer func() {
		if rec := recover(); rec != nil {
			appendLog(fmt.Sprintf("❌ OpenAI Stream panic: %v", rec))
		}
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		appendLog("❌ 不支持流式响应")
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	appendLog(fmt.Sprintf("📥 响应状态: %d", resp.StatusCode))

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		appendLog(fmt.Sprintf("❌ OpenAI 错误 %d: %s", resp.StatusCode, string(body)))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	reader := bufio.NewReaderSize(resp.Body, 128*1024)
	eventCount := 0
	textChunks := 0

	sentDone := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			appendLog(fmt.Sprintf("❌ 读取流失败: %v", err))
			break
		}

		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
			sentDone = true
			break
		}

		eventCount++

		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		textChunks++
	}

	if !sentDone {
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	}

	appendLog(fmt.Sprintf("⬅️ OpenAI Stream 完成，处理了 %d 个事件，%d 个文本块", eventCount, textChunks))
}

func handleAnthropicIncoming(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		appendLog(fmt.Sprintf("❌ 读取请求失败: %v", err))
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var anthropicReq AnthropicRequest
	if err := json.Unmarshal(body, &anthropicReq); err != nil {
		appendLog(fmt.Sprintf("❌ 解析 Anthropic 请求失败: %v", err))
		http.Error(w, "Failed to parse request", http.StatusBadRequest)
		return
	}

	originalModel := anthropicReq.Model
	if strings.Contains(anthropicReq.Model, "/") {
		parts := strings.SplitN(anthropicReq.Model, "/", 2)
		if len(parts) == 2 {
			anthropicReq.Model = parts[1]
		}
	}

	if config.ModelMappings != nil {
		if mappedModel, exists := config.ModelMappings[anthropicReq.Model]; exists {
			appendLog(fmt.Sprintf("🔄 模型映射: %s -> %s", anthropicReq.Model, mappedModel))
			anthropicReq.Model = mappedModel
		}
	}

	if originalModel != anthropicReq.Model {
		appendLog(fmt.Sprintf("📥 Anthropic入站: model=%s (原始: %s), stream=%v", anthropicReq.Model, originalModel, anthropicReq.Stream))
	} else {
		appendLog(fmt.Sprintf("📥 Anthropic入站: model=%s, stream=%v", anthropicReq.Model, anthropicReq.Stream))
	}

	switch config.ProtocolMode {
	case ModeAnthropic:
		appendLog("🔄 Anthropic→Anthropic 透传模式")
		anthropicReq.Stream = true
		anthropicBody, _ := json.Marshal(anthropicReq)
		targetURL := config.TargetURL + "/v1/messages"
		req, err := http.NewRequest("POST", targetURL, nil)
		if err != nil {
			appendLog(fmt.Sprintf("❌ 创建请求失败: %v", err))
			http.Error(w, "Failed to create request", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if apiKey := r.Header.Get("x-api-key"); apiKey != "" {
			req.Header.Set("x-api-key", apiKey)
		} else if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			apiKey := strings.TrimPrefix(authHeader, "Bearer ")
			req.Header.Set("x-api-key", apiKey)
		}
		req.Header.Set("anthropic-version", "2023-06-01")
		resp, err := doRequestWithRetry(req, anthropicBody, 3)
		if err != nil {
			appendLog(fmt.Sprintf("❌ 请求失败: %v", err))
			http.Error(w, "Failed to reach target server", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		handleAnthropicStreamPassthrough(w, resp)

	default:
		openaiReq := convertAnthropicToOpenAIRequest(anthropicReq)
		openaiReq.Stream = true
		appendLog(fmt.Sprintf("🔄 Anthropic→OpenAI 协议转换: model=%s, messages=%d", openaiReq.Model, len(openaiReq.Messages)))

		apiKey := r.Header.Get("x-api-key")
		if apiKey == "" {
			if authHeader := r.Header.Get("Authorization"); authHeader != "" {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		openaiBody, _ := json.Marshal(openaiReq)
		targetURL := config.TargetURL + "/v1/chat/completions"
		appendLog(fmt.Sprintf("📤 目标: %s", targetURL))

		req, err := http.NewRequest("POST", targetURL, nil)
		if err != nil {
			appendLog(fmt.Sprintf("❌ 创建请求失败: %v", err))
			http.Error(w, "Failed to create request", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}

		resp, err := doRequestWithRetry(req, openaiBody, 3)
		if err != nil {
			appendLog(fmt.Sprintf("❌ 请求失败: %v", err))
			http.Error(w, "Failed to reach target server", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		handleOpenAIToAnthropicStream(w, resp, anthropicReq.Model)
	}
}

func handleOpenAIToAnthropicStream(w http.ResponseWriter, resp *http.Response, model string) {
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		appendLog(fmt.Sprintf("❌ OpenAI 错误 %d: %s", resp.StatusCode, string(body[:min(500, len(body))])))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		appendLog("❌ 不支持流式响应")
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	msgID := fmt.Sprintf("msg_%d", time.Now().UnixNano())

	startEvent := map[string]interface{}{
		"type": "message_start",
		"message": map[string]interface{}{
			"id":      msgID,
			"type":    "message",
			"role":    "assistant",
			"model":   model,
			"content": []interface{}{},
			"usage":   map[string]int{"input_tokens": 0, "output_tokens": 0},
		},
	}
	startData, _ := json.Marshal(startEvent)
	fmt.Fprintf(w, "event: message_start\ndata: %s\n\n", startData)
	flusher.Flush()

	blockStarted := false
	contentIdx := 0
	reader := bufio.NewReaderSize(resp.Body, 128*1024)
	eventCount := 0
	textChunks := 0

	emitText := func(text string) {
		if text == "" {
			return
		}
		if !blockStarted {
			blockStart := map[string]interface{}{
				"type":          "content_block_start",
				"index":         contentIdx,
				"content_block": map[string]interface{}{"type": "text", "text": ""},
			}
			bsData, _ := json.Marshal(blockStart)
			fmt.Fprintf(w, "event: content_block_start\ndata: %s\n\n", bsData)
			flusher.Flush()
			blockStarted = true
		}
		delta := map[string]interface{}{
			"type":  "content_block_delta",
			"index": contentIdx,
			"delta": map[string]interface{}{"type": "text_delta", "text": text},
		}
		dData, _ := json.Marshal(delta)
		fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", dData)
		flusher.Flush()
		textChunks++
	}

	emitThinking := func(text string) {
		if text == "" {
			return
		}
		if !blockStarted {
			blockStart := map[string]interface{}{
				"type":          "content_block_start",
				"index":         contentIdx,
				"content_block": map[string]interface{}{"type": "thinking", "thinking": ""},
			}
			bsData, _ := json.Marshal(blockStart)
			fmt.Fprintf(w, "event: content_block_start\ndata: %s\n\n", bsData)
			flusher.Flush()
			blockStarted = true
		}
		delta := map[string]interface{}{
			"type":  "content_block_delta",
			"index": contentIdx,
			"delta": map[string]interface{}{"type": "thinking_delta", "thinking": text},
		}
		dData, _ := json.Marshal(delta)
		fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", dData)
		flusher.Flush()
	}

	closeBlock := func() {
		if blockStarted {
			blockStop := map[string]interface{}{
				"type":  "content_block_stop",
				"index": contentIdx,
			}
			bsData, _ := json.Marshal(blockStop)
			fmt.Fprintf(w, "event: content_block_stop\ndata: %s\n\n", bsData)
			flusher.Flush()
			contentIdx++
			blockStarted = false
		}
	}

	lastWasThinking := false

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			appendLog(fmt.Sprintf("❌ 读取流失败: %v", err))
			break
		}

		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var chunk OpenAIStreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}

		eventCount++

		if len(chunk.Choices) == 0 {
			continue
		}

		choice := chunk.Choices[0]

		if choice.Delta.ReasoningContent != nil {
			thinking, ok := choice.Delta.ReasoningContent.(string)
			if ok && thinking != "" {
				if lastWasThinking == false && blockStarted {
					closeBlock()
				}
				lastWasThinking = true
				emitThinking(thinking)
			}
			continue
		}

		if choice.Delta.Content != nil {
			text, ok := choice.Delta.Content.(string)
			if !ok || text == "" {
				continue
			}
			if lastWasThinking && blockStarted {
				closeBlock()
			}
			lastWasThinking = false
			emitText(text)
		}

		if len(choice.Delta.ToolCalls) > 0 {
			closeBlock()
			for _, tc := range choice.Delta.ToolCalls {
				if tc.ID != "" {
					if blockStarted {
						blockStop := map[string]interface{}{
							"type":  "content_block_stop",
							"index": contentIdx,
						}
						bsData, _ := json.Marshal(blockStop)
						fmt.Fprintf(w, "event: content_block_stop\ndata: %s\n\n", bsData)
						flusher.Flush()
						contentIdx++
						blockStarted = false
					}

					blockStart := map[string]interface{}{
						"type":  "content_block_start",
						"index": contentIdx,
						"content_block": map[string]interface{}{
							"type":  "tool_use",
							"id":    tc.ID,
							"name":  tc.Function.Name,
							"input": map[string]interface{}{},
						},
					}
					bsData, _ := json.Marshal(blockStart)
					fmt.Fprintf(w, "event: content_block_start\ndata: %s\n\n", bsData)
					flusher.Flush()
					blockStarted = true
				}

				if tc.Function.Arguments != "" {
					delta := map[string]interface{}{
						"type":  "content_block_delta",
						"index": contentIdx,
						"delta": map[string]interface{}{
							"type":         "input_json_delta",
							"partial_json": tc.Function.Arguments,
						},
					}
					dData, _ := json.Marshal(delta)
					fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", dData)
					flusher.Flush()
				}
			}
		}

		if choice.FinishReason != "" {
			closeBlock()

			stopReason := "end_turn"
			switch choice.FinishReason {
			case "length":
				stopReason = "max_tokens"
			case "tool_calls":
				stopReason = "tool_use"
			case "stop":
				stopReason = "end_turn"
			}

			msgDelta := map[string]interface{}{
				"type":  "message_delta",
				"delta": map[string]interface{}{"stop_reason": stopReason},
				"usage": map[string]int{"output_tokens": 0},
			}
			mdData, _ := json.Marshal(msgDelta)
			fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n", mdData)
			flusher.Flush()
		}
	}

	msgStop := map[string]interface{}{"type": "message_stop"}
	msData, _ := json.Marshal(msgStop)
	fmt.Fprintf(w, "event: message_stop\ndata: %s\n\n", msData)
	flusher.Flush()

	appendLog(fmt.Sprintf("⬅️ OpenAI→Anthropic Stream 转换完成，处理了 %d 个事件，%d 个文本块", eventCount, textChunks))
}

func handleAnthropicStreamPassthrough(w http.ResponseWriter, resp *http.Response) {
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		appendLog(fmt.Sprintf("❌ Anthropic 错误 %d: %s", resp.StatusCode, string(respBody[:min(500, len(respBody))])))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		appendLog("❌ 不支持流式响应")
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flusher.Flush()

	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			flusher.Flush()
		}
		if err != nil {
			if err != io.EOF {
				appendLog(fmt.Sprintf("❌ 读取流失败: %v", err))
			}
			break
		}
	}
	appendLog("⬅️ Anthropic 透传流式响应完成")
}

func convertAnthropicToOpenAIRequest(req AnthropicRequest) OpenAIRequest {
	openaiReq := OpenAIRequest{
		Model:       req.Model,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stream:      req.Stream,
	}

	if len(req.StopSequences) > 0 {
		openaiReq.Stop = req.StopSequences
	}

	if req.System != "" {
		openaiReq.Messages = append(openaiReq.Messages, OpenAIMessage{
			Role:    "system",
			Content: req.System,
		})
	}

	for _, msg := range req.Messages {
		switch contentBlocks := msg.Content.(type) {
		case string:
			openaiReq.Messages = append(openaiReq.Messages, OpenAIMessage{
				Role:    msg.Role,
				Content: contentBlocks,
			})
		case []interface{}:
			var toolCalls []OpenAIToolCall
			var textParts []interface{}
			var imageParts []interface{}
			var toolResults []map[string]interface{}

			for _, block := range contentBlocks {
				if m, ok := block.(map[string]interface{}); ok {
					blockType, _ := m["type"].(string)
					switch blockType {
					case "text":
						text, _ := m["text"].(string)
						textParts = append(textParts, map[string]interface{}{
							"type": "text",
							"text": text,
						})
					case "image":
						if source, ok := m["source"].(map[string]interface{}); ok {
							sourceType, _ := source["type"].(string)
							if sourceType == "base64" {
								mediaType, _ := source["media_type"].(string)
								data, _ := source["data"].(string)
								if mediaType != "" && data != "" {
									dataURL := "data:" + mediaType + ";base64," + data
									imageParts = append(imageParts, map[string]interface{}{
										"type": "image_url",
										"image_url": map[string]interface{}{
											"url": dataURL,
										},
									})
								}
							} else if sourceType == "url" {
								imgURL, _ := source["url"].(string)
								if imgURL != "" {
									imageParts = append(imageParts, map[string]interface{}{
										"type": "image_url",
										"image_url": map[string]interface{}{
											"url": imgURL,
										},
									})
								}
							}
						}
					case "tool_use":
						id, _ := m["id"].(string)
						name, _ := m["name"].(string)
						input, _ := json.Marshal(m["input"])
						toolCalls = append(toolCalls, OpenAIToolCall{
							ID:   id,
							Type: "function",
							Function: OpenAIFunctionCall{
								Name:      name,
								Arguments: string(input),
							},
						})
					case "tool_result":
						toolResults = append(toolResults, m)
					}
				}
			}

			if msg.Role == "assistant" && len(toolCalls) > 0 {
				assistantMsg := OpenAIMessage{
					Role:      "assistant",
					ToolCalls: toolCalls,
				}
				if len(textParts) == 1 {
					if m, ok := textParts[0].(map[string]interface{}); ok {
						assistantMsg.Content = m["text"]
					}
				} else if len(textParts) > 1 {
					assistantMsg.Content = textParts
				}
				openaiReq.Messages = append(openaiReq.Messages, assistantMsg)
			} else if len(toolResults) > 0 {
				for _, tr := range toolResults {
					toolUseID, _ := tr["tool_use_id"].(string)
					content := ""
					if c, ok := tr["content"].(string); ok {
						content = c
					}
					openaiReq.Messages = append(openaiReq.Messages, OpenAIMessage{
						Role:       "tool",
						Content:    content,
						ToolCallID: toolUseID,
					})
				}
			} else if len(imageParts) > 0 || len(textParts) > 0 {
				var allParts []interface{}
				allParts = append(allParts, textParts...)
				allParts = append(allParts, imageParts...)
				openaiReq.Messages = append(openaiReq.Messages, OpenAIMessage{
					Role:    msg.Role,
					Content: allParts,
				})
			}
		default:
			openaiReq.Messages = append(openaiReq.Messages, OpenAIMessage{
				Role:    msg.Role,
				Content: fmt.Sprintf("%v", msg.Content),
			})
		}
	}

	if len(req.Tools) > 0 {
		for _, tool := range req.Tools {
			openaiReq.Tools = append(openaiReq.Tools, OpenAITool{
				Type: "function",
				Function: OpenAIToolFunction{
					Name:        tool.Name,
					Description: tool.Description,
					Parameters:  tool.InputSchema,
				},
			})
		}
		appendLog(fmt.Sprintf("🔧 转换 %d 个工具定义 (Anthropic→OpenAI)", len(openaiReq.Tools)))
	}

	if len(openaiReq.Messages) == 0 {
		openaiReq.Messages = []OpenAIMessage{{Role: "user", Content: "Hello"}}
	}

	return openaiReq
}

// Anthropic 转换模式
func isRetryableError(err error, statusCode int) (bool, string) {
	if err != nil {
		if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				return true, "请求超时"
			}
			return true, "网络错误"
		}
		errStr := err.Error()
		if strings.Contains(errStr, "connection refused") {
			return true, "连接被拒绝"
		}
		if strings.Contains(errStr, "connection reset") {
			return true, "连接被重置"
		}
		if strings.Contains(errStr, "EOF") {
			return true, "连接意外关闭"
		}
		return true, "请求失败"
	}
	if statusCode >= 500 && statusCode < 600 {
		return true, fmt.Sprintf("服务器错误 %d", statusCode)
	}
	if statusCode == 429 {
		return true, "请求过于频繁"
	}
	return false, ""
}

func doRequestWithRetry(req *http.Request, body []byte, maxRetries int) (*http.Response, error) {
	var resp *http.Response
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		resp, lastErr = httpClient.Do(req)

		statusCode := 0
		if resp != nil {
			statusCode = resp.StatusCode
		}

		shouldRetry, reason := isRetryableError(lastErr, statusCode)
		if !shouldRetry {
			return resp, lastErr
		}

		if resp != nil {
			resp.Body.Close()
		}

		if attempt < maxRetries {
			retryDelay := time.Duration(1<<uint(attempt-1)) * time.Second
			appendLog(fmt.Sprintf("⚠️ %s (尝试 %d/%d)，%.0f秒后重试...", reason, attempt, maxRetries, retryDelay.Seconds()))
			time.Sleep(retryDelay)
		}
	}

	return resp, lastErr
}

func handleAnthropicConvert(w http.ResponseWriter, r *http.Request, openaiReq OpenAIRequest) {
	anthropicReq := convertToAnthropicRequest(openaiReq)

	appendLog(fmt.Sprintf("🔄 转换 Anthropic: model=%s, stream=%v", openaiReq.Model, openaiReq.Stream))

	anthropicBody, _ := json.Marshal(anthropicReq)

	targetURL := config.TargetURL + "/v1/messages"

	req, err := http.NewRequest("POST", targetURL, nil)
	if err != nil {
		appendLog(fmt.Sprintf("❌ 创建请求失败: %v", err))
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		apiKey := strings.TrimPrefix(authHeader, "Bearer ")
		req.Header.Set("x-api-key", apiKey)
	}
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := doRequestWithRetry(req, anthropicBody, 3)
	if err != nil {
		appendLog(fmt.Sprintf("❌ 请求失败: %v", err))
		http.Error(w, "Failed to reach target server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	handleStreamResponse(w, resp, openaiReq.Model)
}

func convertToAnthropicRequest(openaiReq OpenAIRequest) AnthropicRequest {
	anthropicReq := AnthropicRequest{
		Model:       openaiReq.Model,
		Temperature: openaiReq.Temperature,
		TopP:        openaiReq.TopP,
		Stream:      openaiReq.Stream,
	}

	if openaiReq.MaxCompletionTokens > 0 {
		anthropicReq.MaxTokens = openaiReq.MaxCompletionTokens
	} else if openaiReq.MaxTokens > 0 {
		anthropicReq.MaxTokens = openaiReq.MaxTokens
	} else {
		anthropicReq.MaxTokens = 4096
	}

	if openaiReq.Stop != nil {
		switch v := openaiReq.Stop.(type) {
		case string:
			anthropicReq.StopSequences = []string{v}
		case []interface{}:
			for _, s := range v {
				if str, ok := s.(string); ok {
					anthropicReq.StopSequences = append(anthropicReq.StopSequences, str)
				}
			}
		}
	}

	var pendingToolResults []interface{}

	for _, msg := range openaiReq.Messages {
		switch msg.Role {
		case "system":
			anthropicReq.System = getMessageContent(msg.Content)

		case "assistant":
			if len(msg.ToolCalls) > 0 {
				var contentBlocks []interface{}
				textContent := getMessageContent(msg.Content)
				if textContent != "" {
					contentBlocks = append(contentBlocks, map[string]interface{}{
						"type": "text",
						"text": textContent,
					})
				}
				for _, tc := range msg.ToolCalls {
					var input interface{}
					if tc.Function.Arguments != "" {
						json.Unmarshal([]byte(tc.Function.Arguments), &input)
					}
					if input == nil {
						input = map[string]interface{}{}
					}
					contentBlocks = append(contentBlocks, map[string]interface{}{
						"type":  "tool_use",
						"id":    tc.ID,
						"name":  tc.Function.Name,
						"input": input,
					})
				}
				anthropicReq.Messages = append(anthropicReq.Messages, AnthropicMessage{
					Role:    "assistant",
					Content: contentBlocks,
				})
			} else {
				anthropicReq.Messages = append(anthropicReq.Messages, AnthropicMessage{
					Role:    "assistant",
					Content: getMessageContent(msg.Content),
				})
			}

		case "tool":
			pendingToolResults = append(pendingToolResults, map[string]interface{}{
				"type":        "tool_result",
				"tool_use_id": msg.ToolCallID,
				"content":     getMessageContent(msg.Content),
			})

		default:
			if len(pendingToolResults) > 0 {
				anthropicReq.Messages = append(anthropicReq.Messages, AnthropicMessage{
					Role:    "user",
					Content: pendingToolResults,
				})
				pendingToolResults = nil
			}
			anthropicReq.Messages = append(anthropicReq.Messages, AnthropicMessage{
				Role:    "user",
				Content: getAnthropicContent(msg.Content),
			})
		}
	}

	if len(pendingToolResults) > 0 {
		anthropicReq.Messages = append(anthropicReq.Messages, AnthropicMessage{
			Role:    "user",
			Content: pendingToolResults,
		})
	}

	if len(anthropicReq.Messages) == 0 {
		anthropicReq.Messages = []AnthropicMessage{{Role: "user", Content: "Hello"}}
	}

	if len(openaiReq.Tools) > 0 {
		for _, tool := range openaiReq.Tools {
			if tool.Type == "function" {
				anthropicReq.Tools = append(anthropicReq.Tools, AnthropicTool{
					Name:        tool.Function.Name,
					Description: tool.Function.Description,
					InputSchema: tool.Function.Parameters,
				})
			}
		}
		appendLog(fmt.Sprintf("🔧 转换 %d 个工具定义", len(anthropicReq.Tools)))
	}

	return anthropicReq
}

func getMessageContent(content interface{}) string {
	switch v := content.(type) {
	case string:
		return v
	case []interface{}:
		var texts []string
		for _, part := range v {
			if m, ok := part.(map[string]interface{}); ok {
				if t, ok := m["text"].(string); ok {
					texts = append(texts, t)
				}
			}
		}
		return strings.Join(texts, "\n")
	default:
		return fmt.Sprintf("%v", content)
	}
}

func getAnthropicContent(content interface{}) interface{} {
	switch v := content.(type) {
	case string:
		return v
	case []interface{}:
		var contentBlocks []interface{}
		for _, part := range v {
			if m, ok := part.(map[string]interface{}); ok {
				partType, _ := m["type"].(string)
				switch partType {
				case "text":
					if text, ok := m["text"].(string); ok {
						contentBlocks = append(contentBlocks, map[string]interface{}{
							"type": "text",
							"text": text,
						})
					}
				case "image_url":
					if imageURL, ok := m["image_url"].(map[string]interface{}); ok {
						if url, ok := imageURL["url"].(string); ok {
							if strings.HasPrefix(url, "data:") {
								parts := strings.SplitN(url, ",", 2)
								if len(parts) == 2 {
									mediaType := "image/jpeg"
									if strings.Contains(parts[0], "image/png") {
										mediaType = "image/png"
									} else if strings.Contains(parts[0], "image/gif") {
										mediaType = "image/gif"
									} else if strings.Contains(parts[0], "image/webp") {
										mediaType = "image/webp"
									}
									contentBlocks = append(contentBlocks, map[string]interface{}{
										"type": "image",
										"source": map[string]interface{}{
											"type":       "base64",
											"media_type": mediaType,
											"data":       parts[1],
										},
									})
								}
							} else {
								contentBlocks = append(contentBlocks, map[string]interface{}{
									"type": "image",
									"source": map[string]interface{}{
										"type": "url",
										"url":  url,
									},
								})
							}
						}
					}
				}
			}
		}
		if len(contentBlocks) > 0 {
			return contentBlocks
		}
		return getMessageContent(content)
	default:
		return fmt.Sprintf("%v", content)
	}
}

func convertToGeminiRequest(openaiReq OpenAIRequest) GeminiRequest {
	geminiReq := GeminiRequest{
		Contents: []GeminiContent{},
	}

	var systemText string
	for _, msg := range openaiReq.Messages {
		if msg.Role == "system" {
			systemText = getMessageContent(msg.Content)
		}
	}

	for _, msg := range openaiReq.Messages {
		if msg.Role == "system" {
			continue
		}

		role := "user"
		if msg.Role == "assistant" {
			role = "model"
		}

		var parts []GeminiPart

		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			textContent := getMessageContent(msg.Content)
			if textContent != "" {
				parts = append(parts, GeminiPart{Text: textContent})
			}
			for _, tc := range msg.ToolCalls {
				var args map[string]interface{}
				if tc.Function.Arguments != "" {
					json.Unmarshal([]byte(tc.Function.Arguments), &args)
				}
				if args == nil {
					args = map[string]interface{}{}
				}
				parts = append(parts, GeminiPart{
					FunctionCall: &GeminiFunctionCall{
						Name: tc.Function.Name,
						Args: args,
					},
				})
			}
			geminiReq.Contents = append(geminiReq.Contents, GeminiContent{
				Role:  role,
				Parts: parts,
			})
			continue
		}

		if msg.Role == "tool" {
			var respContent interface{}
			content := getMessageContent(msg.Content)
			if err := json.Unmarshal([]byte(content), &respContent); err != nil {
				respContent = map[string]interface{}{"result": content}
			}
			parts = append(parts, GeminiPart{
				FunctionResp: &GeminiFunctionResp{
					Name:     msg.Name,
					Response: respContent,
				},
			})
			geminiReq.Contents = append(geminiReq.Contents, GeminiContent{
				Role:  "user",
				Parts: parts,
			})
			continue
		}

		parts = getGeminiParts(msg.Content)

		if role == "user" && systemText != "" && len(geminiReq.Contents) == 0 {
			parts = append([]GeminiPart{{Text: systemText + "\n\n"}}, parts...)
			systemText = ""
		}

		geminiReq.Contents = append(geminiReq.Contents, GeminiContent{
			Role:  role,
			Parts: parts,
		})
	}

	if len(geminiReq.Contents) == 0 {
		text := "Hello"
		if systemText != "" {
			text = systemText + "\n\n" + text
		}
		geminiReq.Contents = []GeminiContent{
			{Role: "user", Parts: []GeminiPart{{Text: text}}},
		}
	}

	if len(openaiReq.Tools) > 0 {
		var functions []GeminiFunctionDeclaration
		for _, tool := range openaiReq.Tools {
			if tool.Type == "function" {
				functions = append(functions, GeminiFunctionDeclaration{
					Name:        tool.Function.Name,
					Description: tool.Function.Description,
					Parameters:  tool.Function.Parameters,
				})
			}
		}
		if len(functions) > 0 {
			geminiReq.Tools = []GeminiToolConfig{{FunctionDeclarations: functions}}
			appendLog(fmt.Sprintf("🔧 Gemini 转换 %d 个工具定义", len(functions)))
		}
	}

	return geminiReq
}

func getGeminiParts(content interface{}) []GeminiPart {
	switch v := content.(type) {
	case string:
		return []GeminiPart{{Text: v}}
	case []interface{}:
		var parts []GeminiPart
		for _, part := range v {
			if m, ok := part.(map[string]interface{}); ok {
				partType, _ := m["type"].(string)
				switch partType {
				case "text":
					if text, ok := m["text"].(string); ok {
						parts = append(parts, GeminiPart{Text: text})
					}
				case "image_url":
					if imageURL, ok := m["image_url"].(map[string]interface{}); ok {
						if url, ok := imageURL["url"].(string); ok {
							if strings.HasPrefix(url, "data:") {
								urlParts := strings.SplitN(url, ",", 2)
								if len(urlParts) == 2 {
									mimeType := "image/jpeg"
									if strings.Contains(urlParts[0], "image/png") {
										mimeType = "image/png"
									} else if strings.Contains(urlParts[0], "image/gif") {
										mimeType = "image/gif"
									} else if strings.Contains(urlParts[0], "image/webp") {
										mimeType = "image/webp"
									}
									parts = append(parts, GeminiPart{
										InlineData: &GeminiInlineData{
											MimeType: mimeType,
											Data:     urlParts[1],
										},
									})
								}
							}
						}
					}
				}
			}
		}
		if len(parts) > 0 {
			return parts
		}
		return []GeminiPart{{Text: getMessageContent(content)}}
	default:
		return []GeminiPart{{Text: fmt.Sprintf("%v", content)}}
	}
}

func handleGeminiStreamResponse(w http.ResponseWriter, resp *http.Response, originalModel string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		appendLog(fmt.Sprintf("❌ Gemini 错误 %d: %s", resp.StatusCode, string(body)))
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	reader := bufio.NewReaderSize(resp.Body, 256*1024)
	writer := bufio.NewWriterSize(w, 32*1024)
	messageID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	firstChunk := true
	toolCallIndex := 0
	pendingFlush := 0

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			break
		}

		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")

		var geminiResp GeminiResponse
		if err := json.Unmarshal([]byte(data), &geminiResp); err != nil {
			continue
		}

		if len(geminiResp.Candidates) > 0 {
			candidate := geminiResp.Candidates[0]

			if firstChunk {
				chunk := OpenAIStreamChunk{
					ID:      messageID,
					Object:  "chat.completion.chunk",
					Created: time.Now().Unix(),
					Model:   originalModel,
					Choices: []OpenAIChoice{{Index: 0, Delta: OpenAIMessage{Role: "assistant"}}},
				}
				chunkData, _ := json.Marshal(chunk)
				writer.WriteString("data: ")
				writer.Write(chunkData)
				writer.WriteString("\n\n")
				writer.Flush()
				flusher.Flush()
				firstChunk = false
			}

			for _, part := range candidate.Content.Parts {
				if part.Text != "" {
					chunk := OpenAIStreamChunk{
						ID:      messageID,
						Object:  "chat.completion.chunk",
						Created: time.Now().Unix(),
						Model:   originalModel,
						Choices: []OpenAIChoice{{Index: 0, Delta: OpenAIMessage{Content: part.Text}}},
					}
					chunkData, _ := json.Marshal(chunk)
					writer.WriteString("data: ")
					writer.Write(chunkData)
					writer.WriteString("\n\n")
					pendingFlush++

					if pendingFlush >= 5 {
						writer.Flush()
						flusher.Flush()
						pendingFlush = 0
					}
				}

				if part.FunctionCall != nil {
					argsJSON, _ := json.Marshal(part.FunctionCall.Args)
					toolCall := OpenAIToolCall{
						ID:    fmt.Sprintf("call_%d_%d", time.Now().UnixNano(), toolCallIndex),
						Type:  "function",
						Index: toolCallIndex,
						Function: OpenAIFunctionCall{
							Name:      part.FunctionCall.Name,
							Arguments: string(argsJSON),
						},
					}
					chunk := OpenAIStreamChunk{
						ID:      messageID,
						Object:  "chat.completion.chunk",
						Created: time.Now().Unix(),
						Model:   originalModel,
						Choices: []OpenAIChoice{{
							Index: 0,
							Delta: OpenAIMessage{
								ToolCalls: []OpenAIToolCall{toolCall},
							},
						}},
					}
					chunkData, _ := json.Marshal(chunk)
					writer.WriteString("data: ")
					writer.Write(chunkData)
					writer.WriteString("\n\n")
					writer.Flush()
					flusher.Flush()
					toolCallIndex++
				}
			}

			if candidate.FinishReason != "" {
				finishReason := mapGeminiFinishReason(candidate.FinishReason)
				chunk := OpenAIStreamChunk{
					ID:      messageID,
					Object:  "chat.completion.chunk",
					Created: time.Now().Unix(),
					Model:   originalModel,
					Choices: []OpenAIChoice{{Index: 0, Delta: OpenAIMessage{}, FinishReason: finishReason}},
				}
				chunkData, _ := json.Marshal(chunk)
				writer.WriteString("data: ")
				writer.Write(chunkData)
				writer.WriteString("\n\n")
				writer.Flush()
				flusher.Flush()
			}
		}
	}

	writer.WriteString("data: [DONE]\n\n")
	writer.Flush()
	flusher.Flush()

	appendLog("⬅️ Gemini Stream 完成")
}

func mapGeminiFinishReason(reason string) string {
	switch reason {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY":
		return "content_filter"
	case "RECITATION":
		return "content_filter"
	case "FUNCTION_CALL":
		return "tool_calls"
	default:
		return "stop"
	}
}

func handleStreamResponse(w http.ResponseWriter, resp *http.Response, originalModel string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		appendLog(fmt.Sprintf("❌ Anthropic 错误 %d: %s", resp.StatusCode, string(body)))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	reader := bufio.NewReaderSize(resp.Body, 128*1024)
	messageID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	eventCount := 0
	textChunks := 0

	toolCalls := make(map[int]*OpenAIToolCall)

	sentDone := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			appendLog(fmt.Sprintf("❌ 读取流失败: %v", err))
			break
		}

		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "event: ") || !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
			sentDone = true
			break
		}

		var event AnthropicStreamEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}

		eventCount++
		chunk := convertStreamEvent(event, messageID, originalModel, toolCalls)
		if chunk != nil {
			chunkData, _ := json.Marshal(chunk)
			_, writeErr := fmt.Fprintf(w, "data: %s\n\n", chunkData)
			if writeErr != nil {
				break
			}
			flusher.Flush()

			if len(chunk.Choices) > 0 {
				if content, ok := chunk.Choices[0].Delta.Content.(string); ok && content != "" {
					textChunks++
				}
			}
		}
	}

	if !sentDone {
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	}

	appendLog(fmt.Sprintf("⬅️ Stream 完成，处理了 %d 个事件，%d 个文本块", eventCount, textChunks))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func toTitleCase(s string) string {
	words := strings.Fields(s)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(string(word[0])) + strings.ToLower(word[1:])
		}
	}
	return strings.Join(words, " ")
}

func convertStreamEvent(event AnthropicStreamEvent, messageID, originalModel string, toolCalls map[int]*OpenAIToolCall) *OpenAIStreamChunk {
	switch event.Type {
	case "content_block_start":
		if event.ContentBlock != nil && event.ContentBlock.Type == "thinking" {
			return nil
		}
		if event.ContentBlock != nil && event.ContentBlock.Type == "tool_use" {
			toolCall := &OpenAIToolCall{
				ID:    event.ContentBlock.ID,
				Type:  "function",
				Index: event.Index,
				Function: OpenAIFunctionCall{
					Name:      event.ContentBlock.Name,
					Arguments: "",
				},
			}
			toolCalls[event.Index] = toolCall

			return &OpenAIStreamChunk{
				ID:      messageID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   originalModel,
				Choices: []OpenAIChoice{{
					Index: 0,
					Delta: OpenAIMessage{
						ToolCalls: []OpenAIToolCall{*toolCall},
					},
				}},
			}
		}

	case "content_block_delta":
		if event.Delta != nil {
			if event.Delta.Type == "thinking_delta" && event.Delta.Thinking != "" {
				return &OpenAIStreamChunk{
					ID:      messageID,
					Object:  "chat.completion.chunk",
					Created: time.Now().Unix(),
					Model:   originalModel,
					Choices: []OpenAIChoice{{Index: 0, Delta: OpenAIMessage{ReasoningContent: event.Delta.Thinking}}},
				}
			}

			if event.Delta.Text != "" {
				return &OpenAIStreamChunk{
					ID:      messageID,
					Object:  "chat.completion.chunk",
					Created: time.Now().Unix(),
					Model:   originalModel,
					Choices: []OpenAIChoice{{Index: 0, Delta: OpenAIMessage{Content: event.Delta.Text}}},
				}
			}

			if event.Delta.PartialJson != "" {
				if tool, ok := toolCalls[event.Index]; ok {
					tool.Function.Arguments += event.Delta.PartialJson

					return &OpenAIStreamChunk{
						ID:      messageID,
						Object:  "chat.completion.chunk",
						Created: time.Now().Unix(),
						Model:   originalModel,
						Choices: []OpenAIChoice{{
							Index: 0,
							Delta: OpenAIMessage{
								ToolCalls: []OpenAIToolCall{{
									Index: event.Index,
									Function: OpenAIFunctionCall{
										Arguments: event.Delta.PartialJson,
									},
								}},
							},
						}},
					}
				}
			}
		}

	case "message_start":
		return &OpenAIStreamChunk{
			ID:      messageID,
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   originalModel,
			Choices: []OpenAIChoice{{Index: 0, Delta: OpenAIMessage{Role: "assistant"}}},
		}

	case "message_delta":
		if event.Delta != nil && event.Delta.StopReason != "" {
			finishReason := mapStopReason(event.Delta.StopReason)
			return &OpenAIStreamChunk{
				ID:      messageID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   originalModel,
				Choices: []OpenAIChoice{{Index: 0, Delta: OpenAIMessage{}, FinishReason: finishReason}},
			}
		}
	}
	return nil
}

func mapStopReason(anthropicReason string) string {
	switch anthropicReason {
	case "end_turn":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "stop_sequence":
		return "stop"
	default:
		return "stop"
	}
}

// ==================== 证书和系统操作 ====================

func generateCertificates() error {
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return err
	}

	caKeyGen, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"OpenAI Proxy CA"}, CommonName: "OpenAI Proxy Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKeyGen.PublicKey, caKeyGen)
	if err != nil {
		return err
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(caCertFile, caCertPEM, 0644); err != nil {
		return err
	}

	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKeyGen)})
	if err := os.WriteFile(caKeyFile, caKeyPEM, 0600); err != nil {
		return err
	}

	caCertParsed, _ := x509.ParseCertificate(caCertDER)

	for _, domain := range proxyDomains {
		if err := generateDomainCert(domain, caCertParsed, caKeyGen); err != nil {
			return err
		}
	}
	return nil
}

func generateDomainCert(domain string, caCertParam *x509.Certificate, caKeyParam *rsa.PrivateKey) error {
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain, "*." + domain},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCertParam, &serverKey.PublicKey, caKeyParam)
	if err != nil {
		return err
	}

	safeName := strings.ReplaceAll(domain, ".", "_")
	certFile := fmt.Sprintf("%s/cert_%s.crt", certsDir, safeName)
	keyFile := fmt.Sprintf("%s/cert_%s.key", certsDir, safeName)

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	if err := os.WriteFile(certFile, serverCertPEM, 0644); err != nil {
		return err
	}

	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	return os.WriteFile(keyFile, serverKeyPEM, 0600)
}

func getOrCreateCert(domain string) (*tls.Certificate, error) {
	if cached, ok := certCache.Load(domain); ok {
		return cached.(*tls.Certificate), nil
	}

	safeName := strings.ReplaceAll(domain, ".", "_")
	certFile := fmt.Sprintf("%s/cert_%s.crt", certsDir, safeName)
	keyFile := fmt.Sprintf("%s/cert_%s.key", certsDir, safeName)

	if _, err := os.Stat(certFile); err == nil {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err == nil {
			certCache.Store(domain, &cert)
			return &cert, nil
		}
	}

	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}

	serverCertDER, _ := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverKey.PublicKey, caKey)

	cert := &tls.Certificate{
		Certificate: [][]byte{serverCertDER},
		PrivateKey:  serverKey,
	}

	certCache.Store(domain, cert)
	return cert, nil
}

func modifyHosts(add bool) error {
	hostsPath := `C:\Windows\System32\drivers\etc\hosts`
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	marker := "# OpenAI Proxy"

	for _, line := range lines {
		shouldKeep := true
		for _, domain := range proxyDomains {
			if strings.Contains(line, domain) {
				shouldKeep = false
				break
			}
		}
		if strings.Contains(line, marker) {
			shouldKeep = false
		}
		if shouldKeep {
			newLines = append(newLines, line)
		}
	}

	for len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) == "" {
		newLines = newLines[:len(newLines)-1]
	}

	if add {
		newLines = append(newLines, "")
		newLines = append(newLines, marker)
		for _, domain := range proxyDomains {
			newLines = append(newLines, fmt.Sprintf("127.0.0.1 %s", domain))
		}
	}

	return os.WriteFile(hostsPath, []byte(strings.Join(newLines, "\n")), 0644)
}

func installCACert() error {
	cleanupOldCerts()
	absPath, _ := filepath.Abs(caCertFile)
	cmd := exec.Command("certutil", "-addstore", "-f", "ROOT", absPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_, err := cmd.CombinedOutput()
	return err
}

func uninstallCACert() {
	cmd := exec.Command("certutil", "-delstore", "ROOT", "OpenAI Proxy Root CA")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.CombinedOutput()
}

func cleanupOldCerts() {
	oldCertNames := []string{
		"AI Proxy Root CA",
		"OpenAI Proxy Root CA",
	}
	for _, name := range oldCertNames {
		cmd := exec.Command("certutil", "-delstore", "ROOT", name)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.CombinedOutput()
	}
}
