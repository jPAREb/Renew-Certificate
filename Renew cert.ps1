Function Exportar-Certificat ($idioma)
{
    $array_return = @()
    #Ubicació on es troba els certificats d'Equitrac
    $rutaCert = 'Cert:\CurrentUser\Equitrac-Shared'
    #$rutaRoot = Read-Host 'Ruta root Equitrac (ej. C:\Program Files\Equitrac\Express)'
    $rutaRoot = "C:\Program Files\Equitrac\Express"
    $rutaTools = -join ($rutaRoot, '\tools')
    $rutaCertEq = -join ($rutaRoot, '\tools\certificats')
    $ruutaExportar = -join($rutaRoot, '\Tools\certificats\cert_exportat.pfx')

    if(!(Test-Path -path $rutaCertEq)){

        New-Item -ItemType Directory -Path $rutaCertEq | Out-Null
    }
    $certificats = Get-ChildItem -Path $rutaCert
    $certificatsTaula = @()
    #Variable que incrementarà al foreach. Serveix com identificador alhora de triar
    $i=1
    #Ensenyar per pantalla els certificats d'Equitrac
    foreach ($certificat in $certificats)
    {
        $certificat | Add-Member -MemberType NoteProperty "ID" -Value $i
        $certificatsTaula += $certificat
        $i++
    }
    Write-OutPut $certificatsTaula | Select-Object -Property 'ID', 'NotBefore', 'NotAfter', 'Thumbprint', 'Issuer' | Format-Table
    if($idioma -eq 1)
    {
        $idCertificat = Read-Host "Escriu l'ID del certificat que vols renovar"
    }
    if($idioma -eq 2)
    {
        $idCertificat = Read-Host "Escribe el ID del certificado que quieres renovar"
    }
    if($idioma -eq 3)
    {
        $idCertificat = Read-Host "Type the certificate ID that you want to renew"
    }
    $Thumbprint_Certificat = ($certificatsTaula | where {$_.ID -eq $idCertificat}).Thumbprint
    $contrassenya_segura = ConvertTo-SecureString -String 'R1c0H' -Force -AsPlainText
    Get-ChildItem -Path $rutaCert | where {$_.Thumbprint -eq $Thumbprint_Certificat} | Export-PfxCertificate -FilePath $ruutaExportar -Password $contrassenya_segura | Out-Null
    $CertificatIssuer = (Get-ChildItem -Path $rutaCert | where {$_.Thumbprint -eq $Thumbprint_Certificat}).Subject -replace "CN=",""
    #$CertificatIssuer = $CertificatIssuer[0]

    Write-Host $CertificatIssuer

    Regenerar-Certificat -CertificatIssuer $CertificatIssuer -rutaTools $rutaTools -rutaCertEq $rutaCertEq -ruutaExportar $ruutaExportar -idioma $idioma

}

Function Regenerar-Certificat ($CertificatIssuer, $rutaTools, $rutaCertEq, $ruutaExportar, $idioma)
{
    Write-Host $Rutes_Noms
    if ($idioma -eq 1)
    {
        $UbiOpenSSLconf = Read-Host 'Ubicació OpenSSL.cnf'
    }
    if ($idioma -eq 2)
    {
        $UbiOpenSSLconf = Read-Host 'Ubicación OpenSSL.cnf'
    }
    if ($idioma -eq 3)
    {
        $UbiOpenSSLconf = Read-Host 'OpenSSL.cnf path'
    }
    
    #$UbiOpenSSLconf = "C:\Users\Administrator\Desktop\SSL CERTIFICADOS"
    $OpenSSL = -join ($rutaTools,'\openssl.exe')
    $OpenSSLconf = -join($UbiOpenSSLconf, '\openssl.cnf')
    $CertRegenerat = -join($rutaCertEq,'\cert_final.pfx')
    $CN_issuer = -join('/CN=',$CertificatIssuer)
    $RutaNouCert = -join($rutaCertEq, '\new-certificate.key')
    $RutaNouCert_crt = -join($rutaCertEq, '\new-certificate.crt')
    
    $Env:openssl_conf = $OpenSSLconf
    Set-Location -Path $rutaTools
    #Start-Process -Wait -FilePath $OpenSSL -ArgumentList "pkcs12 -in $ruutaExportar -nocerts -nodes -out 'C:\Program Files\Equitrac\Express\Tools\certificats\new-certificate.key'"
    #Start-Process -Wait -FilePath $OpenSSL -ArgumentList "req -new -key 'C:\Program Files\Equitrac\Express\Tools\certificats\new-certificate.key' -x509 -days 3650 -out 'C:\Program Files\Equitrac\Express\Tools\certificats\new-certificate.crt' -subj $CN_issuer"
    #Start-Process -Wait -FilePath $OpenSSL -ArgumentList "pkcs12 -export -out 'C:\Program Files\Equitrac\Express\Tools\certificats\equitrac2.pfx' -inkey 'C:\Program Files\Equitrac\Express\Tools\certificats\new-certificate.key' -in 'C:\Program Files\Equitrac\Express\Tools\certificats\new-certificate.crt'"
    

    $ExportarClau = -join("pkcs12 -in ",'"',$ruutaExportar,'"'," -nocerts -nodes -out ",'"',$RutaNouCert,'"', ' -passin pass:R1c0H')
    $NovaClau = -join("req -new -key ",'"', $RutaNouCert, '"'," -x509 -days 3650 -out ",'"',$RutaNouCert_crt,'"'," -subj ", $CN_issuer)
    $NouCertificat = -join("pkcs12 -export -out ", '"', $CertRegenerat, '"', " -inkey ",'"', $RutaNouCert,'"', " -in ", '"', $rutaCertEq,'\new-certificate.crt', '"', ' -passout pass:R1c0H')
    Write-Host $NouCertificat
    Start-Process .\openssl.exe -Argumentlist $ExportarClau -Wait
    Start-Process .\openssl.exe -Argumentlist $NovaClau -Wait
    Start-Process .\openssl.exe -Argumentlist $NouCertificat -Wait

    Remove-Item -Path $RutaNouCert
    Remove-Item -Path $RutaNouCert_crt
    Importar-Cert -RutaCertFinal $CertRegenerat -idioma $idioma
}

Function Importar-Cert ($RutaCertFinal, $idioma)
{
    

    if($idioma -eq 1)
    {
        $PararServeis = Read-Host 'Parem serveis (S/n)'
        $BorrarCertificats = Read-Host 'Borrem certificats (S/n)'
        $ImportemCertificat = Read-Host 'Importem certificat (S/n)'
    }
    if($idioma -eq 2)
    {
        $PararServeis = Read-Host 'Paramos servicios (S/n)'
        $BorrarCertificats = Read-Host 'Borramos certificados (S/n)'
        $ImportemCertificat = Read-Host 'Importamos certificado (S/n)'
    }
    if($idioma -eq 3)
    {
        $PararServeis = Read-Host 'Stop Services(Y/n)'
        $BorrarCertificats = Read-Host 'Delete certificates (Y/n)'
        $ImportemCertificat = Read-Host 'Import certificate (Y/n)'
    }

    $rutaCert = 

    if(($PararServeis -eq 's') -or ($PararServeis -eq 'S'))
    {
        Stop-Service -Name EQCASSrv
        Stop-Service -Name EQDRESrv
        Stop-Service -Name EQSLPSrv
        Stop-Service -Name EQSchSrv
    }

    if(($BorrarCertificats -eq 's') -or ($BorrarCertificats -eq 'S') -or ($BorrarCertificats -eq 'Y') -or ($BorrarCertificats -eq 'y'))
    {
        while($idCertificat -ne 999)
        {
            $certificats = Get-ChildItem -Path 'Cert:\CurrentUser\Equitrac-Shared'
            $certificatsTaula = @()
            $i=1
            foreach ($certificat in $certificats)
            {
                $certificat | Add-Member -MemberType NoteProperty "ID" -Value $i
                $certificatsTaula += $certificat
                $i++
            }
            Write-OutPut $certificatsTaula | Select-Object -Property 'ID', 'NotBefore', 'NotAfter', 'Thumbprint', 'Issuer' | Format-Table
            if($idioma -eq 1)
            {
                $idCertificat = Read-Host "Escriu l'ID del certificat que vols borrar (999 per sortir)"
            }
            if($idioma -eq 2)
            {
                $idCertificat = Read-Host "Escribe el ID del certificado que quieres borrar (999 para salir)"
            }
            if($idioma -eq 3)
            {
                $idCertificat = Read-Host "Type the certificate ID that you want to delete (999 to leave)"
            }
            
            $Thumbprint_Certificat = ($certificatsTaula | where {$_.ID -eq $idCertificat}).Thumbprint
            $CertBorrar = -join('Cert:\CurrentUser\Equitrac-Shared\',$Thumbprint_Certificat)
            Get-ChildItem $CertBorrar | Remove-Item
        }
    }

    if(($ImportemCertificat -eq 's') -or ($ImportemCertificat -eq 'S') -or ($ImportemCertificat -eq 'y') -or ($ImportemCertificat -eq 'y'))
    {
        $contrassenya_segura = ConvertTo-SecureString -String 'R1c0H' -Force -AsPlainText
        Import-PfxCertificate -Exportable -FilePath $CertRegenerat -CertStoreLocation 'Cert:\CurrentUser\Equitrac-Shared\' -Password $contrassenya_segura
    
    }

    if(($PararServeis -eq 's') -or ($PararServeis -eq 'S') -or ($PararServeis -eq 'Y') -or ($PararServeis -eq 'y'))
    {
        Start-Service -Name EQCASSrv
        Start-Service -Name EQDRESrv
        Start-Service -Name EQSLPSrv
        Start-Service -Name EQSchSrv
    }
}

Function Select-Idioma
{

    $idioma = Read-Host 'Català [1], Castellano [2], English [3]'

    if($idioma -eq 1)
    {
        Exportar-Certificat -idioma 1
    }
    if($idioma -eq 2)
    {
        Exportar-Certificat -idioma 2
    }
    if($idioma -eq 3)
    {
        Exportar-Certificat -idioma 3
    }

}

Select-Idioma

###########################################
#             by: JORDI PARÉ              #
###########################################