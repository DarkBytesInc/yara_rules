rule Win_Trojan_VGEN_554
{
strings:
	$a0 = { 2781c5d3fd81ed02d58bfdbd71452bef8bfdb8e70a23c791b88f4380e11fd3e8968b852d0c8bced3c8ba0d04f7e2bac56ff7e287852d0c8befb86f3dba6dd1f7e2ba9855f7ea968bc5b105d3c803c696b86f3dba6dd1f7e2ba9855f7ea938bc62bc3b105d3c097474775a7bd0895b109d3ed8bf58beb03eeb103d3cdc482ad13525939e134033a691a4f374302694865dbf0bc908c9dd7d3e0c9083ecb5670ca4a36a8a05f8e01bf4051abbbfa }

condition:
	$a0
}

        