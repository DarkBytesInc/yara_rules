rule Win_Dropper_Microjoin_14
{
strings:
	$a0 = { eb156d6c53d7f5c6efe13a6e163b71082e4dbb47311210d4115e5b85e015c724902c813edbf15716121b6ccf36af09b5fd0a1d059cbed0d6dcb96b51b36aaba6ee47a45621a12d5a61a4eafa8c13874cda20417cb4546b4aa4cea9bb364d1a9a6cc9eece0b689af8b5fddb8f5dfbdc7bbeeef97ae7debbcf1f69f7f3ec }

condition:
	$a0
}

        
