rule Win_Downloader_Banload_1957
{
strings:
	$a0 = { fb35a725880c29a4b088ffa8d9fe5d7e2f4b14d2745b32ab152592fc3f46bae4f6d09b3262920876547adaded9ee33cba78b55148383ff05941a36a744dbde6f35864fe7a0565a3221083965c352dd5a405016bef2f474289b5ff652ff19fe82e2fbef789f0e16ab6636a283ffd328cf5abe1af32fb9fbc8d1f92276e95d9d9ed4716ef70b73e448ae6c6431 }

condition:
	$a0
}

        