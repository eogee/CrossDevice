#requires -Version 5.1
<#
.SYNOPSIS
    CrossDevice 自签证书生成工具（TLS 1.3 / TOFU 用，S1 证书生成链）。

.DESCRIPTION
    生成 RSA 2048 自签证书，把证书与私钥以 PEM 格式落盘（cert.pem / key.pem，
    UTF-8 无 BOM、base64 每行 64 字符），供 Python 标准库
    ssl.SSLContext.load_cert_chain() 直接加载（接口契约第 4.1 章）。

    实测路径（Windows PowerShell 5.1 / .NET Framework 4.8，已实机验证，详见 docs/偏差记录.md 偏差 4）：
        New-SelfSignedCertificate（CurrentUser\My，-KeyExportPolicy Exportable，密钥 ExportPolicy=AllowPlaintextExport）
        -> GetRSAPrivateKey() 直接读 store 证书 -> ExportParameters(true) 导出 RSA 参数
        -> 手工拼 ASN.1 DER -> PKCS#8 未加密私钥（-----BEGIN PRIVATE KEY-----）。
    注意：提示词原定的"PFX 重导入"路线实测失败——PFX 导入的 CNG 密钥不带明文导出策略，
    ExportParameters(true) 报"不支持请求的操作"（Exportable|EphemeralKeySet 与
    Exportable|UserKeySet 两种组合均如此），故直读 store 证书，无需 PFX 环节。

    清理策略：先删证书 store 条目，再按容器名删除残留 CNG 密钥文件
    （Remove-Item 删证书不保证删除 %APPDATA%\Microsoft\Crypto\Keys 下的密钥文件）。

    兼容 Windows PowerShell 5.1（.NET Framework 4.8+），无需管理员权限，无第三方依赖。
    本脚本文件自身必须保存为 UTF-8 with BOM（PS 5.1 按 BOM 识别中文源码编码）。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\gen_cert.ps1
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\gen_cert.ps1 -OutDir D:\tls -HostName NODE-A -Days 3650 -Force

.NOTES
    退出码：0 = 成功；1 = 失败（原因见输出）。
#>
param(
    # 输出目录，默认 %LOCALAPPDATA%\CrossDevice\tls
    [string]$OutDir = '',
    # 证书 CN，默认本机计算机名（控制端只做指纹固定，不做主机名校验，无需 SAN）
    [string]$HostName = $env:COMPUTERNAME,
    # 证书有效期（天）
    [int]$Days = 3650,
    # 覆盖已存在的 cert.pem / key.pem
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

function Info { param([string]$msg) Write-Host ("[信息] " + $msg) }
function Warn { param([string]$msg) Write-Host ("[警告] " + $msg) -ForegroundColor Yellow }
function Fail { param([string]$msg) Write-Host ("[错误] " + $msg) -ForegroundColor Red }

# ---------- ASN.1 DER 编码辅助（无第三方依赖，纯 .NET） ----------

function ConvertTo-DerLength {
    # DER 长度编码：<128 单字节；>=128 用长格式 0x80|字节数
    param([int]$Length)
    if ($Length -lt 0x80) { return [byte[]]@([byte]$Length) }
    $bytes = New-Object System.Collections.Generic.List[byte]
    $v = $Length
    while ($v -gt 0) { $bytes.Insert(0, [byte]($v -band 0xFF)); $v = $v -shr 8 }
    $out = New-Object System.Collections.Generic.List[byte]
    $out.Add([byte](0x80 -bor $bytes.Count))
    $out.AddRange($bytes)
    return $out.ToArray()
}

function ConvertTo-DerTlv {
    # TLV：tag + length + content
    param([byte]$Tag, [byte[]]$Content)
    $lenBytes = [byte[]](ConvertTo-DerLength -Length $Content.Length)  # 显式收敛：PS 会展开函数返回的数组
    $out = New-Object System.Collections.Generic.List[byte]
    $out.Add($Tag); $out.AddRange($lenBytes); $out.AddRange($Content)
    return $out.ToArray()
}

function ConvertTo-DerInteger {
    # DER 正整数：去前导零字节；最高位为 1 时前置 0x00；全零/空按 0 处理
    param([byte[]]$Value)
    if (-not $Value -or $Value.Length -eq 0) { return [byte[]]@(0x02, 0x01, 0x00) }
    $start = 0
    while ($start -lt $Value.Length -and $Value[$start] -eq 0) { $start++ }
    if ($start -eq $Value.Length) { return [byte[]]@(0x02, 0x01, 0x00) }
    $trimmed = $Value[$start..($Value.Length - 1)]
    if ($trimmed[0] -ge 0x80) { $trimmed = [byte[]](@([byte]0x00) + @($trimmed)) }
    return ConvertTo-DerTlv -Tag 0x02 -Content $trimmed
}

function ConvertTo-DerSequence {
    # SEQUENCE (0x30)
    param([object[]]$Parts)
    $body = New-Object System.Collections.Generic.List[byte]
    foreach ($part in $Parts) { $body.AddRange([byte[]]$part) }
    return ConvertTo-DerTlv -Tag 0x30 -Content $body.ToArray()
}

function ConvertTo-Pem {
    # PEM：label 包裹 + base64 每行 64 字符 + CRLF（Python ssl 可加载）
    param([string]$Label, [byte[]]$DerBytes)
    $b64 = [Convert]::ToBase64String($DerBytes)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("-----BEGIN $Label-----`r`n")
    for ($i = 0; $i -lt $b64.Length; $i += 64) {
        $n = [Math]::Min(64, $b64.Length - $i)
        [void]$sb.Append($b64.Substring($i, $n)).Append("`r`n")
    }
    [void]$sb.Append("-----END $Label-----`r`n")
    return $sb.ToString()
}

function Remove-StoreCertAndKey {
    # 清理本脚本本次生成的证书：先删 store 条目，再按容器名删残留 CNG 密钥文件
    param([string]$Thumbprint, [string]$CngKeyName, [string]$CngKeyProvider)
    if ($Thumbprint) {
        try {
            $storePath = 'Cert:\CurrentUser\My\' + $Thumbprint
            if (Test-Path -LiteralPath $storePath) {
                Remove-Item -LiteralPath $storePath -Force -ErrorAction Stop
                Info '清理：证书 store 条目（Cert:\CurrentUser\My）已删除'
            }
        } catch {
            Warn ("清理证书 store 失败：" + $_.Exception.Message)
        }
    }
    if ($CngKeyName -and $CngKeyProvider) {
        try {
            $prov = New-Object System.Security.Cryptography.CngProvider($CngKeyProvider)
            if ([System.Security.Cryptography.CngKey]::Exists($CngKeyName, $prov, [System.Security.Cryptography.CngKeyOpenOptions]::UserKey)) {
                $ng = [System.Security.Cryptography.CngKey]::Open($CngKeyName, $prov, [System.Security.Cryptography.CngKeyOpenOptions]::UserKey)
                $ng.Delete(); $ng.Dispose()
                Info '清理：残留 CNG 私钥文件已删除'
            }
        } catch {
            Warn ("清理 CNG 私钥文件失败：" + $_.Exception.Message)
        }
    }
}

# ---------- 主流程 ----------

$storeThumb = ''
$cngKeyName = ''
$cngKeyProvider = ''

try {
    Info ("CrossDevice 自签证书生成工具（PowerShell " + $PSVersionTable.PSVersion + "，用户 " + $env:USERNAME + "，无需管理员权限）")

    # 0) 参数校验与默认值
    if (-not $HostName) { Fail '-HostName 不能为空（默认取 %COMPUTERNAME%，请显式指定）'; exit 1 }
    if ($Days -lt 1) { Fail "-Days 必须为正整数（当前值 $Days）"; exit 1 }
    if (-not $OutDir) {
        if (-not $env:LOCALAPPDATA) { Fail '无法确定默认输出目录：%LOCALAPPDATA% 未设置，请用 -OutDir 显式指定'; exit 1 }
        $OutDir = Join-Path $env:LOCALAPPDATA 'CrossDevice\tls'
    }
    try { $OutDir = [System.IO.Path]::GetFullPath($OutDir) } catch {}
    $certPath = Join-Path $OutDir 'cert.pem'
    $keyPath  = Join-Path $OutDir 'key.pem'
    Info ("输出目录: " + $OutDir)
    Info ("证书 CN: " + $HostName + " ；有效期: " + $Days + " 天（至 " + (Get-Date).AddDays($Days).ToString('yyyy-MM-dd') + "）")

    # 1) 覆盖检查
    if ((Test-Path -LiteralPath $certPath) -or (Test-Path -LiteralPath $keyPath)) {
        if (-not $Force) {
            Fail ("目标文件已存在：" + $certPath + " / " + $keyPath + "（覆盖请加 -Force）")
            exit 1
        }
        if (Test-Path -LiteralPath $keyPath) {
            # 旧 key.pem 可能已收紧为仅读（无 DELETE 权限），先放宽 ACL 再删
            & icacls.exe $keyPath /reset *> $null
            Remove-Item -LiteralPath $keyPath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $certPath) {
            Remove-Item -LiteralPath $certPath -Force -ErrorAction SilentlyContinue
        }
        if ((Test-Path -LiteralPath $certPath) -or (Test-Path -LiteralPath $keyPath)) {
            Fail '-Force 覆盖失败：旧文件删除不成功（请手动检查文件 ACL/占用）'
            exit 1
        }
        Info '已按 -Force 覆盖既有 cert.pem / key.pem'
    }

    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

    # 2) 生成证书（CurrentUser\My，无需管理员）
    Info '[1/6] 生成 RSA 2048 自签证书（Cert:\CurrentUser\My）...'
    $genParams = @{
        Subject            = "CN=$HostName"
        KeyAlgorithm       = 'RSA'
        KeyLength          = 2048
        KeyUsage           = 'DigitalSignature', 'KeyEncipherment'
        Type               = 'SSLServerAuthentication'   # EKU = Server Authentication
        KeyExportPolicy    = 'Exportable'
        NotAfter           = (Get-Date).AddDays($Days)
        CertStoreLocation  = 'Cert:\CurrentUser\My'
        FriendlyName       = "CrossDevice node ($HostName)"
    }
    $storeCert = New-SelfSignedCertificate @genParams
    $storeThumb = $storeCert.Thumbprint
    Info ("      已生成：SHA-1 Thumbprint = " + $storeThumb + "（store 清理用，非契约指纹）")

    # 3) 直接从 store 证书导出 RSA 参数（实测关键点：-KeyExportPolicy Exportable
    #    会授予密钥 CNG AllowPlaintextExport 策略，ExportParameters(true) 可直接成功；
    #    提示词原定的 PFX 重导入路线实测失败，见脚本头注释与偏差记录 4）
    Info '[2/6] 读取私钥并导出 RSA 参数（.NET GetRSAPrivateKey -> ExportParameters(true)）...'
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($storeCert)
    if (-not $rsa) { Fail 'GetRSAPrivateKey 返回空（密钥不是 RSA 或不可访问）'; exit 1 }
    try {
        $cngKeyName = $rsa.Key.KeyName
        $cngKeyProvider = $rsa.Key.Provider.Provider
        $policy = $rsa.Key.ExportPolicy.ToString()
        Info ("      CNG 密钥容器: " + $cngKeyName + " ；导出策略: " + $policy)
        if ($policy -notlike '*AllowPlaintextExport*') {
            Fail "私钥不具备明文导出策略（$policy），无法导出 PEM；请确认 -KeyExportPolicy Exportable"
            exit 1
        }
    } catch {
        Warn ("读取 CNG 密钥元数据失败（不影响导出本身）：" + $_.Exception.Message)
    }
    try {
        $p = $rsa.ExportParameters($true)
    } catch {
        Fail ("ExportParameters(true) 失败：" + $_.Exception.Message)
        exit 1
    } finally {
        try { if ($rsa) { $rsa.Dispose() } } catch {}
    }
    Info ("      RSA 参数 OK：Modulus=" + $p.Modulus.Length + "B, P=" + $p.P.Length + "B, Q=" + $p.Q.Length + "B")

    # 4) 手工拼 PKCS#8（PrivateKeyInfo：version=0 + rsaEncryption + PKCS#1 RSAPrivateKey）
    Info '[3/6] 手工 DER 编码 PKCS#8 未加密私钥...'
    $rsaVer = [byte[]]@(0x02, 0x01, 0x00)                                  # INTEGER 0
    $pkcs1 = ConvertTo-DerSequence @(
        $rsaVer,
        (ConvertTo-DerInteger $p.Modulus),
        (ConvertTo-DerInteger $p.Exponent),
        (ConvertTo-DerInteger $p.D),
        (ConvertTo-DerInteger $p.P),
        (ConvertTo-DerInteger $p.Q),
        (ConvertTo-DerInteger $p.DP),
        (ConvertTo-DerInteger $p.DQ),
        (ConvertTo-DerInteger $p.InverseQ)
    )
    $rsaOid  = [byte[]]@(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01)  # 1.2.840.113549.1.1.1
    $algNull = [byte[]]@(0x05, 0x00)
    $algId     = ConvertTo-DerSequence @($rsaOid, $algNull)
    $privOctet = ConvertTo-DerTlv -Tag 0x04 -Content $pkcs1                # OCTET STRING 包 PKCS#1
    $pkcs8     = ConvertTo-DerSequence @($rsaVer, $algId, $privOctet)
    Info ("      PKCS#8 DER = " + $pkcs8.Length + " 字节（PKCS#1 内层 " + $pkcs1.Length + " 字节）")

    # 5) 写 PEM（UTF-8 无 BOM —— 关键：不能用 Out-File/Set-Content 默认编码）
    Info '[4/6] 写入 cert.pem / key.pem（UTF-8 无 BOM，base64 每行 64 字符）...'
    $certDer = $storeCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($keyPath,  (ConvertTo-Pem 'PRIVATE KEY'  $pkcs8),   $utf8NoBom)
    [System.IO.File]::WriteAllText($certPath, (ConvertTo-Pem 'CERTIFICATE' $certDer), $utf8NoBom)

    # 6) 收紧 key.pem 权限（移除继承，仅当前用户可读）；cert.pem 保持默认（当前用户可读）
    Info '[5/6] 收紧 key.pem 权限（icacls /inheritance:r /grant:r 当前用户:R）...'
    $grantUser = "$($env:USERNAME):R"
    & icacls.exe $keyPath /inheritance:r /grant:r $grantUser *> $null
    if ($LASTEXITCODE -ne 0) {
        Warn "icacls 首选授权（$grantUser）失败，尝试 COMPUTERNAME\USERNAME 形式..."
        & icacls.exe $keyPath /inheritance:r /grant:r "$($env:COMPUTERNAME)\$($env:USERNAME):R" *> $null
        if ($LASTEXITCODE -ne 0) {
            Fail "key.pem 权限收紧失败（icacls 退出码 $LASTEXITCODE）"
            exit 1
        }
    }
    $aclText = (& icacls.exe $keyPath 2>&1 | Where-Object { $_ -match '\S' }) -join ' ; '
    Info ("      key.pem 当前 ACL：" + $aclText)

    # 指纹（契约 4.1 口径：证书 DER 的 SHA-256，小写 64 hex）
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $fingerprint = ([BitConverter]::ToString($sha.ComputeHash($certDer)) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }

    Info '[6/6] 清理临时对象（证书 store 条目 + CNG 私钥文件，不留垃圾）...'
    Remove-StoreCertAndKey -Thumbprint $storeThumb -CngKeyName $cngKeyName -CngKeyProvider $cngKeyProvider
    $storeThumb = ''
    $cngKeyName = ''
    $cngKeyProvider = ''
    try { $storeCert.Reset() } catch {}
    $storeCert = $null

    Info ("证书 SHA-256 指纹（TOFU 固定口径，契约 4.1）: " + $fingerprint)
    Info ("完成。cert.pem = " + $certPath)
    Info ("       key.pem = " + $keyPath + "（权限已收紧：仅 " + $env:USERNAME + " 可读）")
    exit 0
}
catch {
    Fail ("发生异常：" + $_.Exception.Message)
    if ($_.Exception.InnerException) { Fail ("内部异常：" + $_.Exception.InnerException.Message) }
    exit 1
}
finally {
    # 兜底清理：仅在 [6/6] 尚未清完（变量仍非空，即异常/提前退出路径）时执行
    if ($storeThumb -or $cngKeyName -or $cngKeyProvider) {
        Remove-StoreCertAndKey -Thumbprint $storeThumb -CngKeyName $cngKeyName -CngKeyProvider $cngKeyProvider
    }
}
