rule Win_Downloader_Agent_562
{
strings:
	$a0 = { 7f92f4eeb69905eb374150e8e61975166dc8b3735afcffff5bc7081337ebed260799b3770d1b2fee22ee82cd6d4b5d17f897083514644c6f59156ed15beefe42ff065d83386c73af8e452db97ca514782b1b10fca5a68b16fac74a2de367fcb7feff0fbb74b680 }

condition:
	$a0
}

        
