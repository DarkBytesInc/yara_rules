rule Win_Spyware_690_2
{
strings:
	$a0 = { 3f69537ff9317cc5fbf76e495bd37ed4f7b57284e05dee5fccad9ca483f31c90afffe5be4536ed9dc662a5d747f7095487562f00eeadf554f6ccc66b8fe1163b6f6ed8b6a6d70e16cc01235fc4d7e294a18c51540ddf08c3472e123ca61040 }

condition:
	$a0
}

        
