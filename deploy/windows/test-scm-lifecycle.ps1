param(
  [Parameter(Mandatory = $true)]
  [string]$BinaryPath,
  [Parameter(Mandatory = $true)]
  [string]$WintunDllPath
)

$ErrorActionPreference = 'Stop'
$binary = [IO.Path]::GetFullPath($BinaryPath)
$wintunDll = [IO.Path]::GetFullPath($WintunDllPath)
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "mini-tunnel binary not found: $binary" }
if (-not (Test-Path -LiteralPath $wintunDll -PathType Leaf)) { throw "Wintun DLL not found: $wintunDll" }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Windows SCM/Wintun lifecycle test requires Administrator rights.'
}

$runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { [guid]::NewGuid().ToString('N') }
$attempt = if ($env:GITHUB_RUN_ATTEMPT) { $env:GITHUB_RUN_ATTEMPT } else { '1' }
$instance = "${runId}_$attempt"
$serviceName = "MiniTunnelCI_$instance"
$temporaryRoot = Join-Path $env:RUNNER_TEMP "mini-tunnel-scm-$instance"
$programRoot = Join-Path $env:ProgramFiles "mini-tunnel-ci\$instance"
$stateRoot = Join-Path $env:ProgramData "mini-tunnel-ci\$instance"
$stateDir = Join-Path $stateRoot 'state'
$adminStateDir = Join-Path $temporaryRoot 'admin-state'
$coordinatorState = Join-Path $temporaryRoot 'coordinator.json'
$coordinatorStdout = Join-Path $temporaryRoot 'coordinator.stdout.log'
$coordinatorStderr = Join-Path $temporaryRoot 'coordinator.stderr.log'
$networkId = [guid]::NewGuid().ToString()
$runNumeric = [math]::Abs([long]$runId.GetHashCode())
$subnetOctet = ($runNumeric % 200) + 20
$cidr = "10.252.$subnetOctet.0/24"
$servicePort = 0
$coordinatorProcess = $null
$serviceCreated = $false
$cleanupErrors = [Collections.Generic.List[string]]::new()
$memberDeviceId = $null
$adminToken = $null
$coordinatorUrl = $null
$testRoute = $cidr
$originalDefaultRoutes = @(
  Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
    ForEach-Object { "$($_.InterfaceIndex):$($_.NextHop):$($_.RouteMetric)" }
)

function Get-FreeLoopbackPort {
  $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
  $listener.Start()
  try { return $listener.LocalEndpoint.Port }
  finally { $listener.Stop() }
}

function Invoke-MiniTunnel {
  param([Parameter(Mandatory = $true)][string[]]$Arguments)
  $output = & $binary @Arguments 2>&1
  $exitCode = $LASTEXITCODE
  $text = ($output | Out-String).Trim()
  if ($exitCode -ne 0) {
    throw "mini-tunnel $($Arguments -join ' ') exited $exitCode`: $text"
  }
  return $text
}

function Wait-ServiceOnline {
  param(
    [Parameter(Mandatory = $true)][string]$StatusUrl,
    [Parameter(Mandatory = $true)][string]$Address
  )
  for ($second = 0; $second -lt 45; $second++) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
      try {
        $response = Invoke-WebRequest -Uri $StatusUrl -TimeoutSec 2
        $null = $response.Content | ConvertFrom-Json
        $addressFound = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Address -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200 -and $addressFound) {
          return $addressFound[0].InterfaceAlias
        }
      } catch { }
    }
    Start-Sleep -Seconds 1
  }
  $serviceLog = Join-Path $stateRoot 'service.log'
  if (Test-Path -LiteralPath $serviceLog) {
    Get-Content -LiteralPath $serviceLog -Tail 80 | Write-Output
  }
  throw 'SCM service, loopback status endpoint, and assigned Wintun IPv4 did not become ready within 45 seconds.'
}

function Wait-ServiceStopped {
  param([int]$TimeoutSeconds = 30)
  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  if ($service) { $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds($TimeoutSeconds)) }
}

try {
  New-Item -ItemType Directory -Path $temporaryRoot,$programRoot,$stateRoot,$stateDir,$adminStateDir -Force | Out-Null
  Copy-Item -LiteralPath $wintunDll -Destination (Join-Path $programRoot 'wintun.dll') -Force
  Copy-Item -LiteralPath $binary -Destination (Join-Path $programRoot 'mini-tunnel.exe') -Force
  $installedBinary = Join-Path $programRoot 'mini-tunnel.exe'
  $installedDll = Join-Path $programRoot 'wintun.dll'
  $expectedDllHash = (Get-FileHash -LiteralPath $wintunDll -Algorithm SHA256).Hash
  if ((Get-FileHash -LiteralPath $installedDll -Algorithm SHA256).Hash -ne $expectedDllHash) {
    throw 'Wintun DLL copy changed its SHA-256.'
  }

  & icacls.exe $programRoot /inheritance:r /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not restrict SCM program directory ACL.' }
  & icacls.exe $stateRoot /inheritance:r /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not restrict SCM state directory ACL.' }

  $coordinatorPort = Get-FreeLoopbackPort
  $servicePort = Get-FreeLoopbackPort
  $coordinatorUrl = "http://127.0.0.1:$coordinatorPort"
  $listenAddress = "127.0.0.1:$coordinatorPort"
  $coordinatorArguments = @(
    'coordinator','serve','--listen',$listenAddress,'--state-file',$coordinatorState
  ) -join ' '
  $coordinatorProcess = Start-Process -FilePath $installedBinary -ArgumentList $coordinatorArguments `
    -WorkingDirectory $temporaryRoot -RedirectStandardOutput $coordinatorStdout `
    -RedirectStandardError $coordinatorStderr -PassThru

  $coordinatorReady = $false
  for ($attemptIndex = 0; $attemptIndex -lt 30; $attemptIndex++) {
    if ($coordinatorProcess.HasExited) {
      $details = if (Test-Path $coordinatorStderr) { Get-Content $coordinatorStderr -Raw } else { '' }
      throw "Temporary Coordinator exited early: $details"
    }
    try {
      $health = Invoke-MiniTunnel -Arguments @('coordinator','health','--url',$coordinatorUrl)
      if ($health -match 'ok') { $coordinatorReady = $true; break }
    } catch { }
    Start-Sleep -Seconds 1
  }
  if (-not $coordinatorReady) { throw 'Temporary loopback Coordinator did not become healthy within 30 seconds.' }

  $createOutput = Invoke-MiniTunnel -Arguments @(
    'network','create','--state-dir',$adminStateDir,'--coordinator-url',$coordinatorUrl,
    '--name',"windows SCM CI $instance",'--cidr',$cidr,'--network-id',$networkId
  )
  $adminMatch = [regex]::Match($createOutput, '(?m)^Admin token \(save now; shown once\): (.+)\r?$')
  if (-not $adminMatch.Success) { throw 'Coordinator network creation did not return the one-time admin token.' }
  $adminToken = $adminMatch.Groups[1].Value.Trim()

  $env:MINI_TUNNEL_ADMIN_TOKEN = $adminToken
  $inviteOutput = Invoke-MiniTunnel -Arguments @(
    'network','invite','--state-dir',$adminStateDir,'--coordinator-url',$coordinatorUrl,'--network-id',$networkId
  )
  $inviteMatch = [regex]::Match($inviteOutput, '(?m)^Invite token[^:]*: (.+)\r?$')
  if (-not $inviteMatch.Success) { throw 'Coordinator invite command did not return a one-time member token.' }
  $invitePath = Join-Path $temporaryRoot 'invite.token'
  [IO.File]::WriteAllText($invitePath, $inviteMatch.Groups[1].Value.Trim(), [Text.Encoding]::ASCII)
  $joinOutput = Invoke-MiniTunnel -Arguments @(
    'network','join','--state-dir',$stateDir,'--coordinator-url',$coordinatorUrl,
    '--network-id',$networkId,'--invite-token-file',$invitePath
  )
  $memberMatch = [regex]::Match($joinOutput, '(?m)^Device: ([0-9a-f]{32})\r?$')
  $addressMatch = [regex]::Match($joinOutput, '(?m)^Virtual IPv4: ([0-9.]+)/([0-9.]+)/([0-9]+)\r?$')
  if (-not $memberMatch.Success -or -not $addressMatch.Success) {
    throw "Network join did not return the expected device and IPv4 lease: $joinOutput"
  }
  $memberDeviceId = $memberMatch.Groups[1].Value
  $assignedIPv4 = $addressMatch.Groups[1].Value
  $prefixLength = $addressMatch.Groups[3].Value
  Remove-Item -LiteralPath $invitePath -Force
  Remove-Item Env:\MINI_TUNNEL_ADMIN_TOKEN -ErrorAction SilentlyContinue

  $env:MINI_TUNNEL_STATUS_LISTEN = "127.0.0.1:$servicePort"
  $serviceConfig = @{
    arguments = @(
      '--state-dir',$stateDir,'peer','tunnel','mesh','--network-id',$networkId,
      '--coordinator-url',$coordinatorUrl,'--manage-route'
    )
    log_file = Join-Path $stateRoot 'service.log'
    status_listen = "127.0.0.1:$servicePort"
    coordinator_ca = $null
  } | ConvertTo-Json -Compress -Depth 4
  $configPath = Join-Path $stateRoot 'service.json'
  [IO.File]::WriteAllText($configPath, $serviceConfig, [Text.UTF8Encoding]::new($false))
  $imagePath = '"{0}" windows-service-host --service-name {1} --config "{2}"' -f $installedBinary,$serviceName,$configPath
  New-Service -Name $serviceName -DisplayName "mini-tunnel CI SCM ($instance)" `
    -Description 'Ephemeral Windows SCM lifecycle test' -BinaryPathName $imagePath -StartupType Manual | Out-Null
  $serviceCreated = $true
  & sc.exe failure $serviceName reset= 86400 actions= 'restart/5000/restart/15000/restart/60000' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not configure SCM restart recovery policy.' }

  Start-Service -Name $serviceName
  $interfaceAlias = Wait-ServiceOnline -StatusUrl "http://127.0.0.1:$servicePort/status" -Address $assignedIPv4
  $initialKeyHash = (Get-FileHash -LiteralPath (Join-Path $stateDir 'device.key') -Algorithm SHA256).Hash
  Write-Output "start=passed service=$serviceName status_http=200 tun_interface=$interfaceAlias ipv4=$assignedIPv4/$prefixLength"

  Restart-Service -Name $serviceName
  $interfaceAlias = Wait-ServiceOnline -StatusUrl "http://127.0.0.1:$servicePort/status" -Address $assignedIPv4
  $restartedKeyHash = (Get-FileHash -LiteralPath (Join-Path $stateDir 'device.key') -Algorithm SHA256).Hash
  if ($restartedKeyHash -ne $initialKeyHash) { throw 'Device identity changed during SCM restart.' }
  Write-Output "restart=passed key_stable=true tun_interface=$interfaceAlias"

  Stop-Service -Name $serviceName
  Wait-ServiceStopped
  $routeGone = $false
  $adapterGone = $false
  for ($second = 0; $second -lt 30; $second++) {
    $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $cidr -ErrorAction SilentlyContinue
    $address = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $assignedIPv4 -ErrorAction SilentlyContinue
    $adapter = Get-NetAdapter -Name $interfaceAlias -ErrorAction SilentlyContinue
    $listener = $false
    $client = [Net.Sockets.TcpClient]::new()
    try {
      $connect = $client.ConnectAsync([Net.IPAddress]::Loopback, $servicePort)
      $listener = $connect.Wait(250) -and $client.Connected
    } catch { }
    finally { $client.Dispose() }
    $routeGone = -not $route
    $addressGone = -not $address
    $adapterGone = -not $adapter
    if ($routeGone -and $addressGone -and $adapterGone -and -not $listener) { break }
    Start-Sleep -Seconds 1
  }
  if (-not $routeGone -or -not $addressGone -or -not $adapterGone -or $listener) {
    throw "SCM stop leaked route/interface/status listener (routeGone=$routeGone addressGone=$addressGone adapterGone=$adapterGone listener=$listener)."
  }
  Write-Output 'stop=passed route_removed=true tun_address_removed=true tun_adapter_removed=true status_listener_closed=true'

  $currentDefaultRoutes = @(
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
      ForEach-Object { "$($_.InterfaceIndex):$($_.NextHop):$($_.RouteMetric)" }
  )
  if (Compare-Object $originalDefaultRoutes $currentDefaultRoutes) {
    throw 'Windows default route changed during SCM test.'
  }
  Write-Output 'default_route=unchanged'
}
catch {
  Write-Output "SCM lifecycle diagnostic: $($_.Exception.Message)"
  $serviceLog = Join-Path $stateRoot 'service.log'
  if (Test-Path -LiteralPath $serviceLog) { Get-Content -LiteralPath $serviceLog -Tail 120 | Write-Output }
  if (Test-Path -LiteralPath $coordinatorStderr) { Get-Content -LiteralPath $coordinatorStderr -Tail 80 | Write-Output }
  throw
}
finally {
  Remove-Item Env:\MINI_TUNNEL_STATUS_LISTEN -ErrorAction SilentlyContinue
  Remove-Item Env:\MINI_TUNNEL_ADMIN_TOKEN -ErrorAction SilentlyContinue
  Remove-Item Env:\MINI_TUNNEL_COORDINATOR_CA_CERT_FILE -ErrorAction SilentlyContinue
  if ($serviceCreated) {
    try {
      $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
      if ($service -and $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service -Name $serviceName -ErrorAction Stop
      }
      Wait-ServiceStopped -TimeoutSeconds 30
      & sc.exe delete $serviceName | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Could not delete SCM service $serviceName." }
    } catch {
      $cleanupErrors.Add("SCM service cleanup failed: $_")
      Write-Warning $cleanupErrors[$cleanupErrors.Count - 1]
    }
  }
  if ($adminToken -and $memberDeviceId -and $coordinatorProcess -and $coordinatorProcess.HasExited -eq $false) {
    try {
      $env:MINI_TUNNEL_ADMIN_TOKEN = $adminToken
      Invoke-MiniTunnel -Arguments @(
        'network','revoke','--state-dir',$adminStateDir,'--coordinator-url',$coordinatorUrl,
        '--network-id',$networkId,'--device-id',$memberDeviceId
      ) | Write-Output
    } catch { Write-Warning "Temporary test member revocation failed: $_" }
  }
  if ($coordinatorProcess -and -not $coordinatorProcess.HasExited) {
    Stop-Process -Id $coordinatorProcess.Id -Force -ErrorAction SilentlyContinue
    $coordinatorProcess.WaitForExit(10000) | Out-Null
  }
  foreach ($path in @($programRoot,$stateRoot,$temporaryRoot,$wintunDll)) {
    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $path) {
      $cleanupErrors.Add("Temporary test path remains: $path")
    }
  }
  if ($cleanupErrors.Count -gt 0) {
    throw ($cleanupErrors -join [Environment]::NewLine)
  }
}
