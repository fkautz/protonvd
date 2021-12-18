#!/bin/sh
download_file()
{
	YEAR=$1
	echo $YEAR
	wget -N https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$YEAR.json.gz
	cat nvdcve-1.1-$YEAR.json.gz | gzip -d > years/$YEAR.json
}

mkdir -p data/years

cd data

i=2002
end=$(date +"%Y")
end=$(($end+1))
while [ $i -ne $((end)) ]
do
	echo "Downloading: $i"
	download_file "$i"
	i=$(($i+1))
done

wget -N https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz 
cat nvdcve-1.1-modified.json.gz | gzip -d > modified.json
