require(data.table)
require(ggplot2)
require(dplyr)
require(scales)
require(stringr)
#read data
dnsdata<-as.tbl(fread('dns_comparision.csv',sep='[', stringsAsFactors = F, quote = '!' ))
#remove ]
dnsdata$iranresolvedips<-gsub("],", "", paste(dnsdata$iranresolvedips))
dnsdata$usresolvedips<-gsub("]", "", paste(dnsdata$usresolvedips))
#make character a vector
dnsdata$iranresolvedips<-strsplit(dnsdata$iranresolvedips,",")
dnsdata$usresolvedips<-strsplit(dnsdata$usresolvedips,",")
#check if ips are equal
compareDNS <- function(x) {
  #print(length(x[[1]]))
  if (length(x[[1]])==0 & length(x[[2]])==0){
    return ('NO RESPONSE FOR BOTH')
  }else if (all(x[1] %in% x[2])){
    return ('SAME RESPONSE')
  }else if (length(x[[1]])==0 && length(x[[2]])!=0){
    return ('NO FOR IRAN ONLY')
  }else if(length(x[[1]])!=0 && length(x[[2]])==0){
    return ('NO FOR US ONLY')
  }else{
    return ('DIFFERENT IPS')
  }
}
dnsdata$RESULT <- apply(dnsdata[,c('iranresolvedips','usresolvedips')], 1,function(x) compareDNS(x))
ggplot(dnsdata, aes(x=RESULT)) + geom_bar() + coord_flip()
