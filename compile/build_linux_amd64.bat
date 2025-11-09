set RELEASE=%date% %time%
ECHO %RELEASE%
set GOOS=linux
set CGO_ENABLED=0
set GOARCH=amd64

go build -o clash -trimpath  -ldflags="-X 'github.com/metacubex/mihomo/constant.Version=%RELEASE%' -X 'github.com/metacubex/mihomo/constant.BuildTime=%RELEASE%' -w -s" ..