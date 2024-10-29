/*

xbt.h

*/
#ifndef __xbt_h__
#define __xbt_h__

#include "d3d8types.h"

#define FVF_xbt D3DFVF_XYZ

struct xbt_vertex
{
	float x,y,z;
};

const float xbt_OO_POS_SCALE = 0.002508f;
const float xbt_POS_DELTA = 41.065369f;
const float xbt_OO_TEX_SCALE = -61.068704f;
const float xbt_TEX_DELTA = -1000000.000000f;


///////////////////////////////////////////////////////////////////////////////
const int vertex_count_text_0 = 156;
short verts_text_0C[] = 
{
		-29368,-16381,-16375, //	x,y,z
		-32752,-19098,-16375, //	x,y,z
		-31303,-19096,-16375, //	x,y,z
		-28656,-16952,-16375, //	x,y,z
		-27947,-16381,-16375, //	x,y,z
		-24567,-13668,-16375, //	x,y,z
		-26012,-13668,-16375, //	x,y,z
		-28656,-15814,-16375, //	x,y,z
		-31323,-13667,-16375, //	x,y,z
		-32748,-13668,-16375, //	x,y,z
		-26011,-19099,-16375, //	x,y,z
		-24563,-19098,-16375, //	x,y,z
		-17241,-16195,-16375, //	x,y,z
		-16875,-15892,-16375, //	x,y,z
		-23197,-16837,-16375, //	x,y,z
		-17767,-16837,-16375, //	x,y,z
		-17241,-16592,-16375, //	x,y,z
		-17482,-13978,-16375, //	x,y,z
		-17631,-13777,-16375, //	x,y,z
		-18229,-14512,-16375, //	x,y,z
		-17341,-14216,-16375, //	x,y,z
		-18180,-14621,-16375, //	x,y,z
		-18115,-14760,-16375, //	x,y,z
		-17211,-14489,-16375, //	x,y,z
		-18042,-14928,-16375, //	x,y,z
		-17096,-14794,-16375, //	x,y,z
		-17965,-15125,-16375, //	x,y,z
		-16999,-15131,-16375, //	x,y,z
		-17890,-15350,-16375, //	x,y,z
		-17825,-15603,-16375, //	x,y,z
		-16925,-15498,-16375, //	x,y,z
		-17775,-15884,-16375, //	x,y,z
		-23189,-15884,-16375, //	x,y,z
		-24897,-15884,-16375, //	x,y,z
		-24897,-16837,-16375, //	x,y,z
		-24093,-16837,-16375, //	x,y,z
		-24089,-15884,-16375, //	x,y,z
		-17771,-13594,-16375, //	x,y,z
		-23188,-13593,-16375, //	x,y,z
		-22735,-14514,-16375, //	x,y,z
		-23341,-13768,-16375, //	x,y,z
		-23488,-13970,-16375, //	x,y,z
		-23627,-14208,-16375, //	x,y,z
		-22784,-14624,-16375, //	x,y,z
		-22849,-14762,-16375, //	x,y,z
		-23755,-14481,-16375, //	x,y,z
		-22922,-14930,-16375, //	x,y,z
		-23868,-14787,-16375, //	x,y,z
		-22999,-15127,-16375, //	x,y,z
		-23964,-15124,-16375, //	x,y,z
		-23073,-15352,-16375, //	x,y,z
		-24038,-15491,-16375, //	x,y,z
		-23139,-15605,-16375, //	x,y,z
		-24046,-17245,-16375, //	x,y,z
		-23154,-17120,-16375, //	x,y,z
		-23971,-17623,-16375, //	x,y,z
		-23099,-17366,-16375, //	x,y,z
		-23873,-17969,-16375, //	x,y,z
		-23035,-17579,-16375, //	x,y,z
		-22964,-17766,-16375, //	x,y,z
		-23755,-18281,-16375, //	x,y,z
		-22887,-17934,-16375, //	x,y,z
		-23622,-18558,-16375, //	x,y,z
		-22807,-18089,-16375, //	x,y,z
		-23477,-18796,-16375, //	x,y,z
		-22725,-18238,-16375, //	x,y,z
		-23325,-18994,-16375, //	x,y,z
		-23181,-19156,-16375, //	x,y,z
		-17783,-19156,-16375, //	x,y,z
		-18244,-18241,-16375, //	x,y,z
		-17607,-18874,-16375, //	x,y,z
		-17437,-18588,-16375, //	x,y,z
		-18221,-18195,-16375, //	x,y,z
		-18163,-18080,-16375, //	x,y,z
		-17279,-18291,-16375, //	x,y,z
		-18082,-17905,-16375, //	x,y,z
		-17138,-17978,-16375, //	x,y,z
		-17990,-17683,-16375, //	x,y,z
		-17899,-17424,-16375, //	x,y,z
		-17019,-17643,-16375, //	x,y,z
		-17821,-17138,-16375, //	x,y,z
		-16930,-17283,-16375, //	x,y,z
		-16875,-16890,-16375, //	x,y,z
		-14534,-14523,-16375, //	x,y,z
		-9555,-13605,-16375, //	x,y,z
		-15016,-13619,-16375, //	x,y,z
		-10027,-14518,-16375, //	x,y,z
		-9376,-13854,-16375, //	x,y,z
		-15135,-13768,-16375, //	x,y,z
		-9197,-14166,-16375, //	x,y,z
		-15307,-14007,-16375, //	x,y,z
		-9965,-14655,-16375, //	x,y,z
		-9028,-14534,-16375, //	x,y,z
		-9882,-14833,-16375, //	x,y,z
		-9789,-15055,-16375, //	x,y,z
		-8879,-14949,-16375, //	x,y,z
		-9697,-15320,-16375, //	x,y,z
		-8761,-15403,-16375, //	x,y,z
		-9618,-15631,-16375, //	x,y,z
		-8682,-15885,-16375, //	x,y,z
		-9562,-15987,-16375, //	x,y,z
		-8654,-16389,-16375, //	x,y,z
		-9541,-16389,-16375, //	x,y,z
		-8681,-16881,-16375, //	x,y,z
		-9563,-16789,-16375, //	x,y,z
		-8757,-17327,-16375, //	x,y,z
		-9620,-17140,-16375, //	x,y,z
		-8874,-17736,-16375, //	x,y,z
		-9701,-17445,-16375, //	x,y,z
		-9023,-18116,-16375, //	x,y,z
		-9794,-17704,-16375, //	x,y,z
		-15468,-14296,-16375, //	x,y,z
		-14598,-14659,-16375, //	x,y,z
		-14682,-14838,-16375, //	x,y,z
		-15611,-14633,-16375, //	x,y,z
		-14777,-15059,-16375, //	x,y,z
		-15733,-15013,-16375, //	x,y,z
		-14870,-15324,-16375, //	x,y,z
		-15826,-15435,-16375, //	x,y,z
		-14950,-15633,-16375, //	x,y,z
		-15886,-15894,-16375, //	x,y,z
		-15006,-15988,-16375, //	x,y,z
		-15907,-16389,-16375, //	x,y,z
		-15028,-16389,-16375, //	x,y,z
		-15880,-16881,-16375, //	x,y,z
		-15006,-16788,-16375, //	x,y,z
		-15805,-17327,-16375, //	x,y,z
		-14947,-17139,-16375, //	x,y,z
		-15688,-17736,-16375, //	x,y,z
		-14865,-17442,-16375, //	x,y,z
		-15540,-18116,-16375, //	x,y,z
		-14769,-17700,-16375, //	x,y,z
		-9888,-17920,-16375, //	x,y,z
		-9197,-18473,-16375, //	x,y,z
		-9973,-18094,-16375, //	x,y,z
		-9387,-18814,-16375, //	x,y,z
		-10035,-18227,-16375, //	x,y,z
		-14673,-17915,-16375, //	x,y,z
		-15367,-18473,-16375, //	x,y,z
		-14588,-18088,-16375, //	x,y,z
		-15177,-18814,-16375, //	x,y,z
		-14525,-18221,-16375, //	x,y,z
		-9585,-19149,-16375, //	x,y,z
		-14980,-19149,-16375, //	x,y,z
		-4808,-16381,-16375, //	x,y,z
		-8192,-19098,-16375, //	x,y,z
		-6744,-19098,-16375, //	x,y,z
		-4099,-16952,-16375, //	x,y,z
		-1453,-19099,-16375, //	x,y,z
		-2,-19098,-16375, //	x,y,z
		-3386,-16381,-16375, //	x,y,z
		-6764,-13662,-16375, //	x,y,z
		-8188,-13668,-16375, //	x,y,z
		-4099,-15814,-16375, //	x,y,z
		-6,-13714,-16375, //	x,y,z
		-1430,-13678,-16375, //	x,y,z
};
const int index_count_text_0 = 462;
char indices_text_0C[] = 
{
	0,1,1,
	-2,2,1,
	1,1,1,
	-2,2,1,
	1,1,-9,
	7,1,-8,
	10,1,-7,
	-1,7,-6,
	3,-7,3,
	4,-4,1,
	8,1,1,
	-2,2,1,
	1,-4,3,
	2,1,1,
	1,-3,2,
	1,-1,2,
	-1,1,1,
	1,-3,2,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	-1,1,1,
	1,-3,2,
	1,-1,2,
	-18,17,1,
	-17,-1,18,
	-17,17,1,
	1,1,1,
	1,-3,2,
	-16,-1,19,
	-18,18,1,
	1,-20,19,
	1,-1,2,
	-1,1,1,
	-2,2,1,
	1,-4,3,
	2,-1,-1,
	2,-2,3,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	-19,20,-1,
	-19,19,-15,
	-22,18,4,
	-22,22,-1,
	-21,21,18,
	1,-40,39,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	2,-1,-1,
	2,-2,3,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	-1,1,1,
	-2,2,1,
	1,-4,3,
	1,-1,2,
	-1,1,1,
	1,-3,2,
	2,-1,-1,
	2,-2,3,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	2,-1,-1,
	2,-2,3,
	1,-2,1,
	1,-1,2,
	-66,65,1,
	-65,-1,66,
	1,-66,65,
	2,1,1,
	-1,-1,3,
	1,-3,2,
	-3,2,3,
	1,-2,-1,
	-3,5,2,
	-1,-3,5,
	1,-3,2,
	1,-1,2,
	-1,1,1,
	1,-3,2,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	-27,7,21,
	1,-29,28,
	2,-1,-1,
	2,-2,3,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	-21,1,22,
	1,-24,23,
	1,-1,2,
	1,-2,1,
	1,-1,2,
	1,-6,-1,
	7,-7,8,
	1,-2,1,
	1,-1,2,
	1,-2,1,
	2,-7,1,
	7,-1,-6,
	7,-7,5,
	2,-2,-1,
	4,1,1,
	-2,2,1,
	1,1,1,
	-3,1,2,
	1,1,-8,
	9,-2,-7,
	6,4,1,
	-5,5,-2,
	-6,3,3,
	-9,3,6,
};

D3DVECTOR pos_anim_text[2] = 
{
	{-0.229403f,-267.650421f,-103.040421f},	
	{-0.229403f,-141.053757f,-54.439625f} 
};

#endif
