rule Win_Downloader_VB_819
{
strings:
	$a0 = { de9533e72a05574ef863979b9c1475739b5a82a24dd6b00f616761426f7841c177ee8c8f78747a66b596c117457869a2c38d43c0daf4e2ce074f70af151896f2fea5ad1b9a41078e63ae0e53b5438a57ba106b3767233eec7a8a76a9939a910982228e52aba34301b523c8d32209eb44503c89484c307a9a49649c09a5a15dc29501ddb000608b7424248b7c2428fcb28033dba4b302 }

condition:
	$a0
}

        