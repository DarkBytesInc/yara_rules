rule Win_Trojan_Mybot_8376
{
strings:
	$a0 = { 69b167a236f5c0e418ca99c2718ca75b006e35428ee1fca7b7c594139092fa5233a53e6ac3d1e9566a4733d1a657a8819fdcc1e94803c2c4bbe45a9f2f1bfea66a36c28a44dfc945b1417199d298d7c2f70df9cf1f }

condition:
	$a0
}

        
