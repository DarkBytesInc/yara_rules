rule Win_Trojan_Hupigon_285
{
strings:
	$a0 = { ca4e34a706d0b3365eeab362a53e42fdac6282cd2ccee0dcd899338992aa5ea5fcdcb078888d2e3198a721025fdc1241f4a86711ca6da9ba8ec5ad1d059099f7af43dff3bce979b24be78fc484f0ff41784a4753bacb9712ffd668a9a877278983e8777f7154c482e27daf5ccaba }

condition:
	$a0
}

        
