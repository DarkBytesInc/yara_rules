rule Win_Downloader_173_1
{
strings:
	$a0 = { 692d08fa69502c443e818f60de293763df0585f8b9e34675a7786a47f5373bfa120ea2df9a543061d89274a0d7ba894718510c458d3be57d1d545e9f2751f7552ae22f09710f645525314176b78ded5252899daf5aec8651c93ded90cd879444486a24f005393788f7a5dd58ceae411edfffa0502b2c8f1d9ad22a2463c54c549a466c36aa85f011 }

condition:
	$a0
}

        