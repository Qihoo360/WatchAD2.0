package setting

import (
	"iatp/common/database"
)

var SettingsMongo = database.NewMgo("ata", "ata_settings")
var DomainMongo = database.NewMgo("ata", "ata_domain")
var AlarmBypassClient = database.NewMgo("ata", "ata_bypass_alert")
var AlarmMongoClient = database.NewMgo("ata", "ata_alert")
var CacheMongo = database.NewMgo("ata", "ata_cache_event")
var TicketCacheMongo = database.NewMgo("ata", "ata_cache_ticket")
var UserSidCacheMongo = database.NewMgo("ata", "ata_cache_user_sid")
var SourceMongo = database.NewMgo("ata", "ata_source")
var OutSourceMongo = database.NewMgo("ata", "ata_out_source")
var LearnMongo = database.NewMgo("ata", "ata_learn")
var GpoBackMongo = database.NewMgo("ata", "ata_gpo_bak")
var ReplMetaDataMongo = database.NewMgo("ata", "ata_replmetadata")

// var SigmaAlarmMongo = database.NewMgo("ata", "ata_sigma_alert")
var HoneypotMongo = database.NewMgo("ata", "ata_honeypot")
var HoneypotRegisterMongo = database.NewMgo("ata", "ata_honeypot_register")

// wbm
var WbmUserMongo = database.NewMgo("ata_wbm", "user")
var RulesMongo = database.NewMgo("ata_wbm", "rules")

// sigma规则表
// var SigmaFlinkMongo = database.NewMgo("ata_wbm", "sigma_flink_rules")
// var SigmaRulesUpdateMongo = database.NewMgo("ata_wbm", "sigma_rules_update")
// var SigmaFlinkResource = database.NewMgo("ata_wbm", "sigma_flink_resource")
