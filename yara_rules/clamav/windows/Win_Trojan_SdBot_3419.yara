rule Win_Trojan_SdBot_3419
{
strings:
	$a0 = { d8b8f7fe7b9852ce737317f427ac6d5924b4b463ea8f325d0731f591efc543c4b8b5fba77d73e6ca4101ca1281c2065447fadc9c8a3e6a1205403718a74d5059427a625e910f8e9340cb6ea9d454d4e28e327b1529953ad52e7131b5b990e2d1c5bb686f54a1bf5252651f69ca696a8554554fb8f18f229e2e35b79c8cbcd0d56d6bcd6a134d18c786e93faa147989ee }

condition:
	$a0
}

        