rule Win_Downloader_367_1
{
strings:
	$a0 = { 0880eac18b8580fbffff89042480caa98dbd88faffff897c240480e2ff80ee35ff1540a101105d898596feffff8b8596feffffa34ad3011080c563c6853cfaffff6980c95cb1b7c6853dfaffff6ec68547faffff78c68536faffff6e80edadc68543faffff6f80c209c6853f }

condition:
	$a0
}

        
