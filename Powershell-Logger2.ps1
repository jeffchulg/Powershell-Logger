# idée d'amélioration: get-pscallstack pour Fatal et Error
# Roll-over
# Regression: No exit gracefully => add a "break" or "exit(1)" instruction inside the PoSH script
<#
    Log levels:
    Fatal   Highest level: important stuff down
    Error   For example application crashes / exceptions.
    Warn    Incorrect behavior but the application can continue
    Info    Normal behavior like mail sent, user updated profile etc.
    Debug   Executed queries, user authenticated, session expired
    Trace   Begin method X, end method X etc
#>
    
Function New-Logger {
    param (
        [cmdletbinding()]
        [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [string]$LogPath,
        [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [string]$FileName,
        [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $False)]
        [string]$MinimumLevel = "INFO",
        [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $False)]
        [string]$MaximumLevel = "FATAL",
        [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $False)]
        [string]$Padding = "",
        [boolean]$WithTimeAppending = $false,
        [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $False)]
        [boolean]$ShowInConsole = $false,
        [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $False)]
        [boolean]$AppendMode = $false
    )
    
    $Logger = New-Object PSObject
    $Logger | Add-Member -Type NoteProperty -Name TimeAppending -Value $WithTimeAppending
    $Logger | Add-Member -Type NoteProperty -Name Padding       -Value $Padding
    $Logger | Add-Member -Type NoteProperty -Name ShowInConsole -Value $ShowInConsole
    $Logger | Add-Member -Type NoteProperty -Name LogPath       -Value $LogPath
    $Logger | Add-Member -Type NoteProperty -Name LogFileName   -Value $FileName
    $Logger | Add-Member -Type NoteProperty -Name LogFilePath   -Value ""
    $Logger | Add-Member -Type NoteProperty -Name LinePrepend   -Value "%t - %l -%p " #t = time, l = logtype ; p = padding;
    $Logger | Add-Member -Type NoteProperty -Name MinimumLevel  -Value ""
    $Logger | Add-Member -Type NoteProperty -Name MaximumLevel  -Value ""
    $Logger | Add-Member -Type NoteProperty -Name AppendMode    -Value $AppendMode
    $Logger | Add-Member -Type NoteProperty -Name Started       -Value $false
    $Logger | Add-Member -Type NoteProperty -Name Finished      -Value $false
    $Logger | Add-Member -Type NoteProperty -Name WarningCount  -Value 0
    $Logger | Add-Member -Type NoteProperty -Name ErrorCount    -Value 0
    $Logger | Add-Member -Type NoteProperty -Name TimeClock     -Value $([Diagnostics.Stopwatch]::StartNew())
    
    $Logger | Add-Member -Type ScriptMethod -Name SetLoggerPadding -Value {
        param (
            [cmdletbinding()]
            [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
            [string]$Padding
        )
        
        if($Padding -eq $null) {
            $Padding = ""
        }
        
        $Padding = $Padding -replace '\t','    '
        $Padding = $Padding -replace '\r',''
        $Padding = $Padding -replace '\n','|'
        
        $this.Padding = $Padding
    }
       
    $Logger | Add-Member -Type ScriptMethod -Name GetLogTypeId -Value {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true)]
            [string]$LogType
        )
        # sanitizing
        $LogType = $LogType.SubString(0,1).ToUpper()+$LogType.SubString(1).ToLower() 
        $LogType = $LogType.Trim()
        switch ($LogType) {
            "Fatal" { return 6 }
            "Error" { return 5 }
            "Warn"  { return 4 }
            "Info"  { return 3 }
            "Debug" { return 2 }
            "Trace" { return 1 }
            default {
                throw "Unknown log type [$LogType]"
            }
        }
    }  

    $Logger | Add-Member -Type ScriptMethod -Name HasErrorOccurred -Value {
        if($this.ErrorCount -gt 0) {
            return $true 
        }
        return $false
    } 
    
    $Logger | Add-Member -Type ScriptMethod -Name isWritable -Value {
        if((-Not $this.Started) -or ($this.Finished)) {
            return $false
        }
        return $true
    } 
    
    $Logger | Add-Member -Type ScriptMethod -Name ResetErrorCount -Value {
        $this.ErrorCount = 0
    } 
    
    $Logger | Add-Member -Type ScriptMethod -Name GetLogTypeColor -Value {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true)]
            [string]$LogType
        )
        # sanitizing
        $LogType = $LogType.SubString(0,1).ToUpper()+$LogType.SubString(1).ToLower() 
        switch ($LogType) {
            "Fatal" { return "Red" }
            "Error" { return "Red" }
            "Warn"  { return "DarkYellow" }
            "Info"  { return "Green" }
            "Debug" { return "White" }
            "Trace" { return "Gray" }
            default {
                throw "Unknown log type [$LogType]"
            }
        }
    }        
    
    $Logger | Add-Member -Type ScriptMethod -Name Start -Value {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true)]
            [string]$ScriptName,
            [Parameter(Mandatory=$true)]
            [string]$ScriptVersion
        )
        
        Process{
            if($this.Started) {
                throw "Logger can't be started twice !"
            }

            $sFullPath        = Join-Path $($this.LogPath) $($this.LogFileName)
            Write-Debug "logPath [$($this.LogPath)] | Filename [$($this.LogFileName)]" 
            #Check if file exists and delete if it does
            If((Test-Path -Path $sFullPath) -and -Not $this.AppendMode){
                Remove-Item -Path $sFullPath -Force
            }
            
            #Create file and start logging
            New-Item -Path $this.LogPath -Value $this.LogFileName -ItemType File -Force | Out-Null
            
            $this.LogFilePath = $sFullPath
        
            $LogMsg = "***************************************************************************************************`n" +
                      "Started processing at [$([DateTime]::Now)].`n" +
                      "***************************************************************************************************`n" +
                      "`n" +
                      "Running script [$ScriptName] version [$ScriptVersion].`n" +
                      "`n" +
                      "***************************************************************************************************`n" +
                      "`n" 
            Add-Content -Path $this.LogFilePath -Value $LogMsg
            
            if($this.ShowInConsole) {
                Write-Host $LogMsg 
            }
            
            $this.Started = $true
        }
    }
    $Logger | Add-Member -Type ScriptMethod -Name WriteLog -Value {
        [CmdletBinding()]
  
        Param (
            [Parameter(Mandatory=$true)]
            [string]$LogType,
            [Parameter(Mandatory=$true)]
            [string]$LineValue
        )
        Process{
            if(-Not $this.Started) {
                throw "Logger not started. Cannot write to a log file !"
            }
            if($this.Finished) {
                throw "Logger has finished writing to file $($this.LogFilePath) !"
            }
            $currentLogType = $this.GetLogTypeId($LogType)
            
            # Filtering on Log Type 
            if($currentLogType -le $this.MaximumLevel -and $currentLogType -ge $this.MinimumLevel) {
                
                #Formatting lineValue
                $lineHead = $this.LinePrepend
                
                if($this.TimeAppending) {
                    $lineHead = $lineHead.replace("%t",$([DateTime]::Now))
                }
                else {
                    $lineHead = $lineHead.replace("%t - ","")
                }
                
                $lineHead = $lineHead.replace("%l",'{0,5}' -f $LogType)
                $lineHead = $lineHead.replace("%p",$this.Padding)
                
                $lineValuePadding = " " * $lineHead.Length
                $lineCount = 0
                
                # if the line value has multiple lines in it, 
                $LogMsg = $lineHead 
                
                $LineValue -split "`n" | ForEach-Object {
                    if($lineCount -gt 0) {
                        $LogMsg += $lineValuePadding
                    }
                    $LogMsg += $_ -replace '`r',''
                    $lineCount ++
                }
                
                Add-Content -Path $($this.LogFilePath) -Value $LogMsg
          
                #Write to screen for debug mode
                if($this.ShowInConsole) {
                    $currentLogTypeColor = $this.GetLogTypeColor($LogType)
                    Write-Host $LogMsg -ForegroundColor $currentLogTypeColor
                }
            }
            else {
                Write-Debug "Ignoring message with type [$currentLogType]: $LineValue"
            }
        }
    }     
    
    $Logger | Add-Member -Type ScriptMethod -Name Finish -Value {
        Process {
            if($this.Finished) {
                throw "Logger already finished!"
            }
            
            # Reset padding 
            $this.Padding = ""
            
            $this.TimeClock.Stop()
            
            $LogMsg = "Execution completed"
            
            $SuccessfulOutcome = $true
            if($this.ErrorCount -gt 0) {
                $SuccessfulOutcome = $false
            }
            
            if($SuccessfulOutcome) {
                $LogMsg += " successfully without warnings"
                if($this.WarningCount -gt 0) {
                    $LogMsg += " with " + $this.WarningCount + " warning(s)"
                }
            }
            else {
                $LogMsg += " with errors"
            }
            
            $LogMsg += "."
            
            write-host $LogMsg
            write-host "Total duration: $($this.TimeClock.Elapsed.TotalSeconds) seconds.`n"
            
            $this.Info($LogMsg)
            
            $LogMsg =   "`n" + 
                        "***************************************************************************************************`n" +
                        "Finished processing at [$([DateTime]::Now)].`n" +
                        "Total duration: $($this.TimeClock.Elapsed.TotalSeconds) seconds.`n" + 
                        "***************************************************************************************************`n" +
                        "`n" 

            Add-Content -Path $($this.LogFilePath) -Value $LogMsg
            $this.Finished = $true 
        }
    }
    
    $Logger | Add-Member -Type ScriptMethod -Name Fatal -Value {
        Param (
            [Parameter(Mandatory=$true)]
            [string]$LineValue,
            [Parameter(Mandatory=$true)]
            [boolean]$PrepareForExit
        )
        Process {
            $this.ErrorCount++
            $this.WriteLog("Fatal",$LineValue)
            
            If ($PrepareForExit){
                $this.Finish($false,0)
            }
        }
    }   
    
    $Logger | Add-Member -Type ScriptMethod -Name Error -Value {
        Param (
            [Parameter(Mandatory=$true)]
            [string]$LineValue,
            [Parameter(Mandatory=$true)]
            [boolean]$PrepareForExit
        )
        Process {
            $this.ErrorCount++
            $this.WriteLog("Error",$LineValue)
            
            If ($PrepareForExit){
                $this.Finish($false,0)
            }
        }
    }        
    $Logger | Add-Member -Type ScriptMethod -Name Warn -Value {
        Param (
            [Parameter(Mandatory=$true)]
            [string]$LineValue
        )
        Process {
            $this.WarningCount++
            $this.WriteLog("Warn",$LineValue)
        }
    }   
    
    $Logger | Add-Member -Type ScriptMethod -Name Info -Value {
        Param (
            [Parameter(Mandatory=$true)]
            [string]$LineValue
        )
        Process {
            $this.WriteLog("Info",$LineValue)
        }
    }       
    
    $Logger | Add-Member -Type ScriptMethod -Name Debug -Value {
        Param (
            [Parameter(Mandatory=$true)]
            [string]$LineValue
        )
        Process {
            $this.WriteLog("Debug",$LineValue)
        }
    } 
    
    $Logger | Add-Member -Type ScriptMethod -Name Trace -Value {
        Param (
            [Parameter(Mandatory=$true)]
            [string]$LineValue
        )
        Process {
            $this.WriteLog("Trace",$LineValue)
        }
    }    
    
    $Logger | Add-Member -Type ScriptMethod -Name ShowsInConsole -Value {
        return $this.ShowInConsole
    }  
    
    $Logger | Add-Member -Type ScriptMethod -Name SetShowInConsole -Value {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true)]
            [boolean]$Value
        )
        $this.ShowInConsole = $Value
    }  
    
    $Logger | Add-Member -Type ScriptMethod -Name SetMinimumLevel -Value {
        Param (
            [Parameter(Mandatory=$true)]
            [string]$LevelName
        )
        Process {
            $this.MinimumLevel = $this.GetLogTypeId($LevelName)
        }
    }    
    
    $Logger | Add-Member -Type ScriptMethod -Name SetMaximumLevel -Value {
        Param (
            [Parameter(Mandatory=$true)]
            [string]$LevelName
        )
        Process {
            $this.MaximumLevel = $this.GetLogTypeId($LevelName)
        }
    }  

    $Logger | Add-Member -Type ScriptMethod -Name IncreaseIndentation -Value {
        Process {
            $this.Padding += "    "
        }
    }      
    
    $Logger | Add-Member -Type ScriptMethod -Name DecreaseIndentation -Value {
        Process {
            $this.Padding = $this.Padding -replace ".{4}$"
        }
    }      
    
    $Logger | Add-Member -Type ScriptMethod -Name GetFileFullPath -Value {
        $this.LogFilePath
    }     
    $Logger | Add-Member -Type ScriptMethod -Name SwitchLogFile -Value {
        param (
            [Parameter(Mandatory=$true)]
            [string]$newLogPath,
            [Parameter(Mandatory=$true)]
            [string]$newLogName,
            [Parameter(Mandatory=$true)]
            [boolean]$NoContentCopy
        )
        Process {
            if(-Not $this.Started) {
                throw "Logger has not started yet and you want to switch log file!"
            }
            
            if($this.Finished) {
                throw "Internal error: call to switch log file although the logger has finished his job."
            }
            
            $this.Info("An attempt to switch log file has been asked.")
            $this.Debug("    newLogPath     : [$newLogPath]")
            $this.Debug("    newLogName     : [$newLogName]")
            $this.Debug("    NoContentCopy  : [$NoContentCopy]")
            
            [bool] $changedLogDest = $false;
            if(-Not [string]::IsNullOrEmpty($newLogPath)) {
                if([string]::IsNullOrEmpty($newLogName)) {
                    $this.Error("No log name provided for destination log file!")
                    throw "No log name provided for destination log file!"
                }
                
                # ensure the directory exists
                $newLogPath = Resolve-Path $newLogPath
                
                # create the final path for the new log file
                $newLogFilePath = Join-Path $newLogPath $newLogName
                
                # checking path
                if($newLogFilePath -ne $this.LogFilePath) {
                    $changedLogDest = $true
                }
            }
            else {
                $this.Error("No path provided for destination log file!")
                throw "No path provided for destination log file!"
            }
            
            $this.Info("Now taking care to switch logging from $($this.LogFilePath) to $newLogFilePath")
            
            try {
                $previousLogFile  = $this.LogFilePath
                New-Item $newLogPath -type directory -Force | Out-Null
                if($this.AppendMode -eq $false) {
                    Remove-Item $newLogFilePath -Force | Out-Null
                }

                if(-Not $noContentCopy) { # which means copy content
                    $this.Debug("Copying content to new log file")
                    Get-Content "$previousLogFile" | Add-Content "$newLogFilePath"
                    Remove-Item $previousLogFile -Force | Out-Null
                }
                else {
                    $this.Info("The following of the log will be found in [$newLogFilePath]")
                }
                
                # Switching at logger level.
                $this.LogPath     = $newLogPath
                $this.LogFileName = $newLogName
                $this.LogFilePath = $newLogFilePath
                
                $this.Info("Now writing to the log file [$newLogFilePath]")
                
                if($noContentCopy) {
                    $this.Info("Previous execution log can be found in [$previousLogFile]")
                }
            }
            catch {
                # Discovering the full type name of an exception
                $LogMsg =   "Exception caught while trying to switch logfile:`n" +
                            "    " + $_.Exception.gettype().fullName + "`n" + 
                            "    " + $_.Exception.message + "`n" + 
                            "    At $($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
                $this.Fatal($LogMsg,$false)
                throw "Exception caught while trying to switch logfile."
            }            
        }
    }    
    
    $Logger.MinimumLevel = $Logger.GetLogTypeId($MinimumLevel)
    $Logger.MaximumLevel = $Logger.GetLogTypeId($MaximumLevel)
    
    return $Logger
}

<#

Function Set-LoggerOption {
    param (
        [cmdletbinding()]
        [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [PSObject]$Logger,
        [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [string]$OptionName,
        [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [string]$Value
    )
    
    if($Logger.PSobject.Properties.name -match $OptionName) {
        $Logger.$OptionName = $Value 
    }
    else {
        throw "Invalid logger option with name [$OptionName]"
    }
}
#>
    