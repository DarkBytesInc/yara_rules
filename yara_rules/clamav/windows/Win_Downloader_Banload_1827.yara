rule Win_Downloader_Banload_1827
{
strings:
	$a0 = { 9aa39f08e6934e6f3f6985c541ba45293917b6d4c9654f1eef031567500bd4ac08685c205607e11b98db1d2265d304b5c670ae001389058eceb0a29d0933278efe3fa73cd6bacbe2bf3aabe6bed4c4deb75be00e2bc16a8eca71ecaf56c2f132cb80de0ce396270967 }

condition:
	$a0
}

        
