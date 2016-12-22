require(data.table)
require(ggplot2)
require(dplyr)
require(scales)
require(stringr)
#read data
tcphttpdata<-as.tbl(fread('tcp_connect_comparision.csv',sep = ',', stringsAsFactors = F, quote = '!' ))
ggplot(tcphttpdata, aes(x=category)) + geom_bar() + coord_flip()
