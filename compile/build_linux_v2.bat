
@echo offsetlocal

set BUILDTIME=%date% %time%

for /f "delims=" %%i in ('git -C .. rev-parse --short HEAD') do set COMMIT_ID=%%i

set RELEASE=%COMMIT_ID%
set GOOS=linux
set CGO_ENABLED=0
set GOARCH=amd64
set GOAMD64=v2
go build -tags "with_gvisor" -trimpath -buildvcs=false -ldflags="-X 'github.com/metacubex/mihomo/constant.Version=%RELEASE%' -X 'github.com/metacubex/mihomo/constant.BuildTime=%BUILDTIME%' -w -s -buildid=" -v ..