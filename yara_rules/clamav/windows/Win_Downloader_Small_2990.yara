rule Win_Downloader_Small_2990
{
strings:
	$a0 = { 4bc3bb1ce039362e58ff37fa0d4bf8305774d442e0eceb0139fdeba18bca89c6037b6b9d112bad454dbe0748fade97ca0f74877bd697e87c6aa0342e0999b7f7bd41f96d54768f2c0ab9ef1138ef9e3e4ccbbe2516dbd1ea197d891c057c6585b38d5a4bb2f249f5f8fe62b3129b5f2e84ea }

condition:
	$a0
}

        
