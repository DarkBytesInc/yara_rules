rule Win_Downloader_VB_409
{
strings:
	$a0 = { 4e89fd9dfdf169d281f85f69830a67aac8799764fb292a1b7f6386d9df63628d61477573c54add158c9e316b6d1610255968eb2d14427d510ac545121e89c6f3a2 }

condition:
	$a0
}

        
