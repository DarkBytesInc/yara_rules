rule Win_Downloader_Banload_1361
{
strings:
	$a0 = { d6d445a48b3a8341ab23eb565410d0233764974d0ecce78b733b317bf1e7f42dfca48b7b205eb7b41eeeb237ad760bc5d0795d91a24270db9b22a610b6b902b6e6c7af5c9054c9178b9200b920de7348dbd80deeec8173bb06f7e9dffffffcddfef9f3e7f67be7f79e6f9e79ee67bfa6e7cfbfc415bfe2e29a4201d8da0d17488b1a8ba0458b450a8b1288ea }

condition:
	$a0
}

        