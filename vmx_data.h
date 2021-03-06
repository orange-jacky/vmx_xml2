#ifndef VMX_DATA_H
#define VMX_DATA_H

#define MAX_NUM 59

char *VMX_ARR[MAX_NUM][3]={
	{"VMX.ACCT.BLOCKCD.UPD", "C8V2", "帐户锁定码更新服务"}, 
	{"VMX.ACCT.DATA.INQ", "C8V1", ""}, 
	{"VMX.ACCT.DEMOGRAPHIC.INQ", "C8V2", "客户信息查询"}, 
	{"VMX.ACCT.DEMOGRAPHIC.UPD", "C8V2", "客户一般更新"}, 
	{"VMX.ACCT.DIRECT.DB.INQ", "C8V2", "直接转帐查询服务"}, 
	{"VMX.ACCT.DIRECT.DB.UPD", "C8V2", "直接转帐更新服务"}, 
	{"VMX.ACCT.INQ", "C8V2", "帐户查询服务"}, 
	{"VMX.ACCT.MEMO.DB.UPD", "C8V2", "客户MEMO DB更新"}, 
	{"VMX.ACCT.PLAN.PMT.HISTORY.INQ", "C8V2", "还款分配顺序的查询/计划还款历史查询"}, 
	{"VMX.ACCT.PMT.HISTORY.INQ", "C8V2", "还款历史查询服务"}, 
	{"VMX.ACCT.STMT.DATES.INQ", "C8V2", "对帐单日期查询服务"}, 
	{"VMX.ACCT.STMT.INQ", "C8V2", "对帐单查询服务"}, 
	{"VMX.ACCT.TO.CARD.NAV", "C8V2", "帐户至卡片导航服务"}, 
	{"VMX.ACCT.TRANSACTION.INQ", "C8V2", "交易查询服务"}, 
	{"VMX.ACCT.TRANSACTION.INQ", "C8V3", "交易查询服务"}, 
	{"VMX.CARD.ACTIVATION.UPD", "C8V2", "卡片激活服务"}, 
	{"VMX.CARD.BLOCKCD.UPD", "C8V2", "卡片锁定码更新服务"}, 
	{"VMX.CARD.DATA.INQ", "C8V2", "卡片信息查询"}, 
	{"VMX.CARD.DATA.UPD", "C8V2", "卡片一般更新服务"}, 
	{"VMX.CARD.NEWISSUE.RQST", "C8V2", "请求发行新卡服务"}, 
	{"VMX.CARD.PIN.REISSUE.RQST", "C8V2", "请求密码重发服务"}, 
	{"VMX.CMS.REL.ACCTREC.INQ", "C8V1", ""}, 
	{"VMX.CUST.TO.ACCT.NAV", "C8V2", "客户至帐户导航服务"}, 
	{"VMX.CUSTOMER.LOCATE.INQ", "C8V2", "就客户姓名或ID定位的姓名和地址"}, 
	{"VMX.PID.TO.CUST.NAV", "C8V1", "通过证件号查询客户信息"}, 
	{"VMX.ACCT.INQ", "C8V3", "帐户查询服务"}, 
	{"VMX.ACCT.AUTHLIM.UPD", "C8V1", "账户层授权额度覆盖标志的修改"}, 
	{"VMX.ACCT.CRLIMIT.UPD", "C8V3", "客户层额度修改"}, 
	{"VMX.ACTIVE.HISTORY.INQ", "C8V1", "CTA催收记录的查询"}, 
	{"VMX.CARD.INSTFLG.UPD", "C8V1", "自动分期标志的修改"}, 
	{"VMX.CUST.STMTMAIL.UPD", "C8V1", "账单产生标志修改"}, 
	{"VMX.EMBOSSER.MON.TXNLMT.UPD", "C8V1", "卡片层交易金额/笔数限制修改"}, 
	{"VMX.ACCT.PCTID.UPD", "C8V1", "更新帐户的居住地信息"}, 
	{"VMX.ACCT.CARD.DETAIL.INQ", "C8V1", "查询卡片列表及详细信息"}, 
	{"VMX.CUST.ACCT.DETAIL.INQ", "C8V1", "查询帐户列表及详细信息"}, 
	{"VMX.CARD.DATA.UPD", "C8V3", "卡片一般更新服务"}, 
	{"VMX.ACCT.BILLING.HIST.INQ", "C8V1", "查询帐单结单记录"}, 
	{"VMX.ACCT.BILLING.ALLOC.INQ", "C8V1", "帐单结单分配查询"}, 
	{"VMX.ACCT.PMT.ALLOC.INQ", "C8V1", "还款分配查询"}, 
	{"VMX.CARD.BLOCKCD.BATCH.UPD", "C8V1", "批量更新卡片锁定码"}, 
	{"VMX.ACCT.BILLCYC.BATCH.UPD", "C8V1", "批量更新帐单周期"}, 
	{"VMX.ACCT.DEMOGRAPHIC.UPD", "C8V3", "客户一般更新"}, 
	{"VMX.ACCT.STMT.STATISTIC.INQ", "C8V1", "当期帐单信息查询"}, 
	{"VMX.ACCT.CONTACT.HIST.INQ", "C8V1", "ASM帐户操作信息查询"}, 
	{"VMX.CARD.ACTIVITY.INQ", "C8V1", "FAS卡号信息查询"}, 
	{"VMX.ACCT.BALANCE.INQ", "C8V1", "用卡信息查询"}, 
	{"VMX.CARD.REPLACE.RQST", "C8V1", "补卡优化交易"}, 
	{"VMX.ACCT.LIST.INQ", "C8V1", "查询帐号卡号列表"}, 
	{"VMX.CARD.CANCEL.AUTH.RQST", "C8V1", "人工授权取消交易"}, 
	{"VMX.ACCT.MEMO.DB.UPD", "C8V3", "客户memo DB一般更新"}, 
	{"VMX.PHONE.TO.CARD.NAV", "C8V1", "手机号查询卡号"}, 
	{"VMX.ACCT.GENERIC.UPD", "C8V1", "账户信息更新服务"}, 
	{"VMX.CUST.ACCT.CARD.INQ", "C8V1", "通过客户号查询账户层和卡片层信息"}, 
	{"VMX.CUST.ACCT.CARD.INQ", "C8V2", "查询是否能申请预制卡"}, 
	{"VMX.CUST.ADD", "C8V1", "创建客户记录"}, 
	{"VMX.PID.TO.CUST.NAV", "C8V2", "通过证件号查询客户信息"}, 
	{"VMX.CUSTLINKACCT.UPD", "C8V1", "客户信息和预制卡账户、卡片的关联关系建立"}, 
	{"VMX.ECIFID.TO.CUST.NAV", "C8V1", "通过ECIF ID查询客户信息"}, 
	{"VMX.CARD.2IN1REPL.RQST", "C8V1", "存贷合一卡柜台渠道新增补换卡"}
};
#endif
