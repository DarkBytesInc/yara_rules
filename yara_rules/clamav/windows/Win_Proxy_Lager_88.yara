rule Win_Proxy_Lager_88
{
strings:
	$a0 = { d6a2ba8f74ca71598464cce42d4ad58ef1e3ee9690584f4e7096e495b39e78ce2949097521d5fd75eaaeb1fbc0682bf707ad1a30ce38b207d506fe07ba30a30b48bd91f7 }

condition:
	$a0
}

        
