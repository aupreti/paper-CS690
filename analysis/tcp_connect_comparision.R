require(data.table)
require(ggplot2)
library(reshape2)
library(dplyr)    

#read data
tcphttpdata<-as.tbl(fread('tcp_connect_comparision.csv',sep = ',', stringsAsFactors = F, quote = '!' ))
mdat <-melt(tcphttpdata, id.vars=c("category","domain"),
            measure.vars=c("irantcp", "iranhttp"))
mdat <-filter(mdat, value == TRUE)
ggplot(mdat, aes(x=category,fill = variable)) +  geom_bar(position = "dodge") +
  labs(x="Category",y="Count of Success")  +coord_flip()+ scale_fill_discrete(name=element_blank(),
                                                                              breaks=c("irantcp", "iranhttp"),
                                                                              labels=c("TCP success", "HTTP success"))


