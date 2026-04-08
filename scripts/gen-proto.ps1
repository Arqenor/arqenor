# Generate protobuf code for both Go and Rust sides.
# Rust: handled by sentinel-grpc/build.rs (runs automatically with `cargo build`)
# Go:   requires protoc + protoc-gen-go + protoc-gen-go-grpc in PATH
#
# Install Go plugins:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

$ProtoDir = "$PSScriptRoot\..\proto"
$GoOutDir = "$PSScriptRoot\..\go\internal\grpc\generated"

New-Item -ItemType Directory -Force $GoOutDir | Out-Null

Write-Host "Generating Go protobuf stubs..."
protoc `
  --proto_path="$ProtoDir" `
  --go_out="$GoOutDir" --go_opt=paths=source_relative `
  --go-grpc_out="$GoOutDir" --go-grpc_opt=paths=source_relative `
  "$ProtoDir\common.proto" `
  "$ProtoDir\host_analyzer.proto" `
  "$ProtoDir\network_scanner.proto"

if ($LASTEXITCODE -eq 0) {
    Write-Host "Go stubs generated in $GoOutDir"
} else {
    Write-Error "protoc failed — ensure protoc is installed and in PATH"
    exit 1
}

Write-Host "Rust stubs generated automatically by cargo build -p sentinel-grpc"
