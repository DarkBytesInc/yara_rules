rule Win_Downloader_ConHook_3
{
strings:
	$a0 = { 74268a442408538ad88afb8bd1578b7c240cc1e9028bc3c1e010668bc3f3ab8bca83e103f3aa5f5b8b442404c38b4c2404568b74241085f6578bf9740d8b5424108a02880141424e75f78bc75f5ec38b5424048b4c240c5356578b7c24143bd78bc2761b8d340f3bd673144e85c98d540aff74188a1e881a4a4e4975f7eb0d85c974098a1f881a42474975f75f5e5bc3558bec837d10 }

condition:
	$a0
}

        