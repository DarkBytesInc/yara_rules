rule Win_Proxy_DiskMaster_1
{
strings:
	$a0 = { 57788e7adc0880013734a9cb294fcbe93e016ff00359deeefd11d01e070eba1266ba1fc4e7ff9b60baf59f5346a98921145f16b24709ff52f8bf3ab409eeb5af7b0f4041b032457ef256944d62227fd8 }

condition:
	$a0
}

        
