rule Win_Spyware_748_2
{
strings:
	$a0 = { c22240adfa3d9cb0aec2bb3eef02b97c48c9d8a04cbfd456276caa85dd8d4ab3aa69806fbc7e90a0828f69382f2e1265846d112ee611b2a919cb9e05d9f29988ee60206c80388be86cecfdb9708c6b06c699ce87bb34b25ea6d8 }

condition:
	$a0
}

        
