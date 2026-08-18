PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  username TEXT,
  password_hash TEXT NOT NULL,
  referral_code TEXT NOT NULL UNIQUE,
  referred_by INTEGER,
  plan TEXT NOT NULL DEFAULT 'FREE' CHECK(plan IN ('FREE','VIP')),
  vip_until TEXT,
  balance_cents INTEGER NOT NULL DEFAULT 0 CHECK(balance_cents >= 0),
  coins INTEGER NOT NULL DEFAULT 0 CHECK(coins >= 0),
  gems INTEGER NOT NULL DEFAULT 0 CHECK(gems >= 0),
  xp INTEGER NOT NULL DEFAULT 0 CHECK(xp >= 0),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','banned')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (referred_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);
CREATE INDEX IF NOT EXISTS idx_users_referred_by ON users(referred_by);

CREATE TABLE IF NOT EXISTS referral_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  referrer_id INTEGER NOT NULL,
  referred_user_id INTEGER NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
  reward_cents INTEGER NOT NULL DEFAULT 0 CHECK(reward_cents >= 0),
  reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  approved_at TEXT,
  FOREIGN KEY (referrer_id) REFERENCES users(id),
  FOREIGN KEY (referred_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referral_events(referrer_id);
CREATE INDEX IF NOT EXISTS idx_referrals_status ON referral_events(status);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER,
  action TEXT NOT NULL,
  target_user_id INTEGER,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO settings(key,value) VALUES
('maintenance','0'),
('vip_price_cents','999'),
('vip_duration_days','30');

CREATE TABLE IF NOT EXISTS referral_rewards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  referral_id INTEGER NOT NULL,
  referrer_id INTEGER NOT NULL,
  referred_user_id INTEGER NOT NULL,
  reward_cents INTEGER NOT NULL CHECK(reward_cents >= 0),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
  reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  processed_at TEXT,
  FOREIGN KEY (referral_id) REFERENCES referral_events(id),
  FOREIGN KEY (referrer_id) REFERENCES users(id),
  FOREIGN KEY (referred_user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_referral_rewards_referrer ON referral_rewards(referrer_id);
CREATE INDEX IF NOT EXISTS idx_referral_rewards_status ON referral_rewards(status);
INSERT OR IGNORE INTO settings(key,value) VALUES ('referral_reward_cents','100');
INSERT OR IGNORE INTO settings(key,value) VALUES ('referral_requires_approval','1');

CREATE TABLE IF NOT EXISTS admin_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_user_id INTEGER NOT NULL,
  action TEXT NOT NULL,
  target_user_id INTEGER,
  amount_cents INTEGER,
  reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (admin_user_id) REFERENCES users(id),
  FOREIGN KEY (target_user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_admin_actions_target ON admin_actions(target_user_id);
CREATE INDEX IF NOT EXISTS idx_admin_actions_created ON admin_actions(created_at);

CREATE TABLE IF NOT EXISTS game_prizes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  game TEXT NOT NULL CHECK(game IN ('roulette','scratch')),
  label TEXT NOT NULL,
  reward_type TEXT NOT NULL CHECK(reward_type IN ('balance','coins','gems','none')),
  reward_value INTEGER NOT NULL DEFAULT 0 CHECK(reward_value >= 0),
  weight INTEGER NOT NULL DEFAULT 1 CHECK(weight >= 0),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  daily_limit_free INTEGER NOT NULL DEFAULT 1 CHECK(daily_limit_free >= 0),
  daily_limit_vip INTEGER NOT NULL DEFAULT 2 CHECK(daily_limit_vip >= 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_game_prizes_game ON game_prizes(game);

CREATE TABLE IF NOT EXISTS game_plays (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  game TEXT NOT NULL CHECK(game IN ('roulette','scratch')),
  prize_id INTEGER,
  reward_type TEXT NOT NULL CHECK(reward_type IN ('balance','coins','gems','none')),
  reward_value INTEGER NOT NULL DEFAULT 0 CHECK(reward_value >= 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (prize_id) REFERENCES game_prizes(id)
);
CREATE INDEX IF NOT EXISTS idx_game_plays_user_game_date ON game_plays(user_id,game,created_at);

INSERT OR IGNORE INTO game_prizes(id,game,label,reward_type,reward_value,weight,enabled,daily_limit_free,daily_limit_vip)
VALUES
(1,'roulette','Nada','none',0,35,1,1,2),
(2,'roulette','10 Coins','coins',10,30,1,1,2),
(3,'roulette','25 Coins','coins',25,18,1,1,2),
(4,'roulette','1 Gema','gems',1,12,1,1,2),
(5,'roulette','2 Gemas','gems',2,4,1,1,2),
(6,'roulette','R$ 0,10','balance',10,1,1,1,2),
(7,'scratch','Nada','none',0,40,1,1,2),
(8,'scratch','5 Coins','coins',5,25,1,1,2),
(9,'scratch','15 Coins','coins',15,18,1,1,2),
(10,'scratch','1 Gema','gems',1,10,1,1,2),
(11,'scratch','R$ 0,10','balance',10,5,1,1,2),
(12,'scratch','R$ 0,25','balance',25,2,1,1,2);



INSERT OR IGNORE INTO settings(key,value) VALUES ('vip_price_cents','999');
INSERT OR IGNORE INTO settings(key,value) VALUES ('vip_duration_days','30');
INSERT OR IGNORE INTO settings(key,value) VALUES ('vip_support_enabled','1');

CREATE TABLE IF NOT EXISTS withdrawal_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
  pix_key TEXT NOT NULL,
  pix_type TEXT NOT NULL CHECK(pix_type IN ('cpf','cnpj','email','phone','random','manual')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','cancelled')),
  admin_note TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  processed_at TEXT,
  processed_by INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (processed_by) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_withdrawals_user ON withdrawal_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawal_requests(status);

CREATE TABLE IF NOT EXISTS wallet_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('credit','debit','withdrawal_hold','withdrawal_refund','game_reward','referral_reward','admin_credit','admin_debit')),
  amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
  reference_id INTEGER,
  description TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_wallet_user_date ON wallet_transactions(user_id,created_at);

INSERT OR IGNORE INTO settings(key,value) VALUES ('withdrawal_min_cents','1500');

CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','pending','closed')),
  priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('low','normal','high','urgent')),
  assigned_admin INTEGER,
  last_message_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  closed_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (assigned_admin) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_tickets_user ON tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status,last_message_at);

CREATE TABLE IF NOT EXISTS ticket_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_id INTEGER NOT NULL,
  sender_type TEXT NOT NULL CHECK(sender_type IN ('user','admin')),
  sender_id INTEGER NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (ticket_id) REFERENCES tickets(id)
);
CREATE INDEX IF NOT EXISTS idx_ticket_messages_ticket ON ticket_messages(ticket_id,created_at);

INSERT OR IGNORE INTO settings(key,value) VALUES ('ticket_support_enabled','1');
INSERT OR IGNORE INTO settings(key,value) VALUES ('ticket_max_open_per_user','3');

CREATE TABLE IF NOT EXISTS platform_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_by INTEGER
);
INSERT OR IGNORE INTO platform_settings(key,value) VALUES ('maintenance_enabled','0');
INSERT OR IGNORE INTO platform_settings(key,value) VALUES ('maintenance_message','O sistema está em manutenção. Voltaremos em breve.');
INSERT OR IGNORE INTO platform_settings(key,value) VALUES ('maintenance_allow_admin','1');
INSERT OR IGNORE INTO platform_settings(key,value) VALUES ('registration_enabled','1');
INSERT OR IGNORE INTO platform_settings(key,value) VALUES ('referrals_enabled','1');
INSERT OR IGNORE INTO platform_settings(key,value) VALUES ('games_enabled','1');
INSERT OR IGNORE INTO platform_settings(key,value) VALUES ('withdrawals_enabled','1');
INSERT OR IGNORE INTO platform_settings(key,value) VALUES ('tickets_enabled','1');
CREATE INDEX IF NOT EXISTS idx_platform_settings_updated ON platform_settings(updated_at);


CREATE TABLE IF NOT EXISTS notification_preferences (
  user_id INTEGER PRIMARY KEY,
  referrals INTEGER NOT NULL DEFAULT 1,
  wallet INTEGER NOT NULL DEFAULT 1,
  withdrawals INTEGER NOT NULL DEFAULT 1,
  vip INTEGER NOT NULL DEFAULT 1,
  tickets INTEGER NOT NULL DEFAULT 1,
  games INTEGER NOT NULL DEFAULT 1,
  system INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS ranking_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_by INTEGER
);
INSERT OR IGNORE INTO ranking_settings(key,value) VALUES ('enabled','1');
INSERT OR IGNORE INTO ranking_settings(key,value) VALUES ('period','all');
INSERT OR IGNORE INTO ranking_settings(key,value) VALUES ('metric','referrals');

CREATE INDEX IF NOT EXISTS idx_users_xp ON users(xp DESC);
CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);

CREATE TABLE IF NOT EXISTS referral_security (
  user_id INTEGER PRIMARY KEY,
  ip_hash TEXT,
  ua_hash TEXT,
  risk_level TEXT NOT NULL DEFAULT 'low' CHECK(risk_level IN ('low','medium','high')),
  risk_reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_referral_security_ip ON referral_security(ip_hash);
CREATE INDEX IF NOT EXISTS idx_referral_security_risk ON referral_security(risk_level);

CREATE TABLE IF NOT EXISTS referral_risk_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  referral_id INTEGER,
  referrer_id INTEGER,
  referred_user_id INTEGER,
  risk_level TEXT NOT NULL CHECK(risk_level IN ('low','medium','high')),
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (referral_id) REFERENCES referral_events(id),
  FOREIGN KEY (referrer_id) REFERENCES users(id),
  FOREIGN KEY (referred_user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_referral_risk_referral ON referral_risk_events(referral_id);
CREATE INDEX IF NOT EXISTS idx_referral_risk_level ON referral_risk_events(risk_level);


CREATE TABLE IF NOT EXISTS promo_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  duration_days INTEGER,
  benefit_type TEXT NOT NULL DEFAULT 'vip_days' CHECK(benefit_type IN ('vip_days','balance_cents','coins','gems')),
  benefit_value INTEGER NOT NULL DEFAULT 0 CHECK(benefit_value >= 0),
  max_redemptions INTEGER NOT NULL DEFAULT 1 CHECK(max_redemptions > 0),
  redemptions INTEGER NOT NULL DEFAULT 0 CHECK(redemptions >= 0),
  redemption_count INTEGER NOT NULL DEFAULT 0 CHECK(redemption_count >= 0),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','ended','archived')),
  starts_at TEXT,
  ends_at TEXT,
  expires_at TEXT,
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (created_by) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_promo_codes_code ON promo_codes(code);
CREATE INDEX IF NOT EXISTS idx_promo_codes_status ON promo_codes(status,starts_at,ends_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_promo_codes_upper ON promo_codes(code);

CREATE TABLE IF NOT EXISTS promo_redemptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  promo_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  benefit_type TEXT NOT NULL DEFAULT 'vip_days',
  benefit_value INTEGER NOT NULL DEFAULT 0,
  redeemed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(promo_id,user_id),
  FOREIGN KEY (promo_id) REFERENCES promo_codes(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_promo_redemptions_user ON promo_redemptions(user_id,redeemed_at);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL DEFAULT 'system',
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  data_json TEXT,
  read_at TEXT,
  is_read INTEGER NOT NULL DEFAULT 0 CHECK(is_read IN (0,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id,created_at);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(user_id,is_read,created_at);
CREATE INDEX IF NOT EXISTS idx_notifications_unread_legacy ON notifications(user_id,read_at);

CREATE TABLE IF NOT EXISTS partners (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  logo_url TEXT,
  website_url TEXT,
  banner_url TEXT,
  target_url TEXT DEFAULT '',
  placement TEXT NOT NULL DEFAULT 'dashboard',
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','ended','archived')),
  sort_order INTEGER NOT NULL DEFAULT 0,
  starts_at TEXT,
  ends_at TEXT,
  impressions INTEGER NOT NULL DEFAULT 0,
  clicks INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_partners_status_dates ON partners(status,starts_at,ends_at);
CREATE INDEX IF NOT EXISTS idx_partners_placement ON partners(placement);



INSERT OR IGNORE INTO settings(key,value) VALUES ('referral_reward_cents','100');
INSERT OR IGNORE INTO settings(key,value) VALUES ('referral_requires_approval','1');
INSERT OR IGNORE INTO settings(key,value) VALUES ('referral_ip_limit','3');
INSERT OR IGNORE INTO settings(key,value) VALUES ('referral_ua_limit','5');
INSERT OR IGNORE INTO settings(key,value) VALUES ('referral_risk_enabled','1');


CREATE TABLE IF NOT EXISTS partner_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  partner_id INTEGER NOT NULL,
  user_id INTEGER,
  event_type TEXT NOT NULL CHECK(event_type IN ('impression','click')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (partner_id) REFERENCES partners(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_partner_events_partner ON partner_events(partner_id,created_at);



CREATE TABLE IF NOT EXISTS level_settings (
  level INTEGER PRIMARY KEY,
  xp_required INTEGER NOT NULL CHECK(xp_required >= 0),
  title TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO level_settings(level,xp_required,title) VALUES
(1,0,'Iniciante'),(2,100,'Aprendiz'),(3,250,'Ativo'),(4,500,'Veterano'),
(5,1000,'Elite'),(6,2000,'Mestre'),(7,5000,'Lenda');

CREATE TABLE IF NOT EXISTS achievements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  icon TEXT NOT NULL DEFAULT '🏆',
  requirement_type TEXT NOT NULL CHECK(requirement_type IN ('referrals','xp')),
  requirement_value INTEGER NOT NULL CHECK(requirement_value > 0),
  reward_type TEXT NOT NULL DEFAULT 'none' CHECK(reward_type IN ('none','balance','coins','gems')),
  reward_value INTEGER NOT NULL DEFAULT 0 CHECK(reward_value >= 0),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO achievements(code,title,description,icon,requirement_type,requirement_value,reward_type,reward_value) VALUES
('REF_1','Primeiro convite','Aprove uma primeira indicação.','🤝','referrals',1,'coins',25),
('REF_5','Recrutador','Tenha 5 indicações aprovadas.','👥','referrals',5,'coins',100),
('REF_10','Influente','Tenha 10 indicações aprovadas.','🔥','referrals',10,'gems',10),
('XP_100','Primeiros passos','Alcance 100 XP.','⭐','xp',100,'coins',50),
('XP_1000','Elite','Alcance 1.000 XP.','🏆','xp',1000,'gems',25);

CREATE TABLE IF NOT EXISTS user_achievements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  achievement_id INTEGER NOT NULL,
  unlocked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id,achievement_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (achievement_id) REFERENCES achievements(id)
);
CREATE INDEX IF NOT EXISTS idx_user_achievements_user ON user_achievements(user_id,unlocked_at);

CREATE TABLE IF NOT EXISTS xp_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  action TEXT NOT NULL,
  xp INTEGER NOT NULL CHECK(xp > 0),
  reference_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id,action,reference_id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_xp_events_user_date ON xp_events(user_id,created_at);

CREATE TABLE IF NOT EXISTS xp_rules (
  action TEXT PRIMARY KEY,
  xp INTEGER NOT NULL DEFAULT 0 CHECK(xp >= 0),
  daily_limit INTEGER NOT NULL DEFAULT 0 CHECK(daily_limit >= 0),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  description TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO xp_rules(action,xp,daily_limit,enabled,description) VALUES
('daily_login',10,1,1,'Primeiro acesso do dia'),
('vip_login',15,1,1,'Primeiro acesso do dia para VIP'),
('approved_referral',25,0,1,'Indicação aprovada'),
('game_play',2,10,1,'Participação em jogo'),
('achievement',20,0,1,'Conquista desbloqueada');

CREATE TABLE IF NOT EXISTS daily_activity (
  user_id INTEGER NOT NULL,
  activity_date TEXT NOT NULL,
  login_xp INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(user_id,activity_date),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS missions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  period TEXT NOT NULL CHECK(period IN ('daily','weekly')),
  requirement_type TEXT NOT NULL CHECK(requirement_type IN ('referrals','games','login_days','xp')),
  requirement_value INTEGER NOT NULL CHECK(requirement_value > 0),
  reward_type TEXT NOT NULL CHECK(reward_type IN ('xp','coins','gems','balance')),
  reward_value INTEGER NOT NULL CHECK(reward_value > 0),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mission_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mission_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  period_key TEXT NOT NULL,
  progress INTEGER NOT NULL DEFAULT 0,
  completed_at TEXT,
  claimed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(mission_id,user_id,period_key),
  FOREIGN KEY (mission_id) REFERENCES missions(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_mission_progress_user ON mission_progress(user_id,period_key);

INSERT OR IGNORE INTO missions(code,title,description,period,requirement_type,requirement_value,reward_type,reward_value)
VALUES
('DAILY_LOGIN','Acesso diário','Entre no site hoje.','daily','login_days',1,'xp',25),
('DAILY_GAMES','Jogador ativo','Jogue 5 vezes hoje.','daily','games',5,'coins',50),
('WEEKLY_REFERRALS','Recrutador da semana','Tenha 3 indicações aprovadas nesta semana.','weekly','referrals',3,'gems',10);

CREATE TABLE IF NOT EXISTS ranking_rewards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  period TEXT NOT NULL CHECK(period IN ('daily','weekly','monthly')),
  position INTEGER NOT NULL CHECK(position > 0),
  reward_type TEXT NOT NULL CHECK(reward_type IN ('xp','coins','gems','balance')),
  reward_value INTEGER NOT NULL CHECK(reward_value > 0),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  UNIQUE(period,position)
);

CREATE TABLE IF NOT EXISTS ranking_claims (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  period TEXT NOT NULL,
  period_key TEXT NOT NULL,
  position INTEGER NOT NULL,
  reward_type TEXT NOT NULL,
  reward_value INTEGER NOT NULL,
  claimed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id,period,period_key),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

INSERT OR IGNORE INTO ranking_rewards(period,position,reward_type,reward_value) VALUES
('daily',1,'coins',100),('daily',2,'coins',50),('daily',3,'coins',25),
('weekly',1,'gems',50),('weekly',2,'gems',25),('weekly',3,'gems',10),
('monthly',1,'balance',1000),('monthly',2,'balance',500),('monthly',3,'balance',250);


CREATE TABLE IF NOT EXISTS vip_settings (
  id INTEGER PRIMARY KEY CHECK(id=1),
  price_cents INTEGER NOT NULL DEFAULT 999 CHECK(price_cents >= 0),
  duration_days INTEGER NOT NULL DEFAULT 30 CHECK(duration_days > 0),
  daily_game_multiplier REAL NOT NULL DEFAULT 2.0 CHECK(daily_game_multiplier >= 1),
  daily_scratch_multiplier REAL NOT NULL DEFAULT 2.0 CHECK(daily_scratch_multiplier >= 1),
  daily_bonus_xp INTEGER NOT NULL DEFAULT 15 CHECK(daily_bonus_xp >= 0),
  ranking_multiplier REAL NOT NULL DEFAULT 1.5 CHECK(ranking_multiplier >= 1),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO vip_settings(id) VALUES(1);

CREATE TABLE IF NOT EXISTS vip_benefits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  sort_order INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO vip_benefits(code,title,description,sort_order) VALUES
('games','🎰 Mais oportunidades nos jogos','Limites e benefícios extras conforme as regras do painel.',1),
('scratch','🎫 Mais oportunidades nas raspadinhas','Benefício VIP configurável pelo administrador.',2),
('xp','⭐ Bônus de XP','Receba XP adicional no acesso diário VIP.',3),
('ranking','🏆 Bônus no ranking','Multiplicador de pontuação configurável.',4),
('priority','⚡ Prioridade','Atendimento e campanhas VIP podem receber prioridade.',5);

CREATE TABLE IF NOT EXISTS vip_redemptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  source TEXT NOT NULL CHECK(source IN ('support','promo','admin')),
  reference_code TEXT,
  days INTEGER NOT NULL CHECK(days > 0),
  vip_until_before TEXT,
  vip_until_after TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_vip_redemptions_user ON vip_redemptions(user_id,created_at);

CREATE TABLE IF NOT EXISTS fraud_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  event_type TEXT NOT NULL,
  risk_score INTEGER NOT NULL DEFAULT 0 CHECK(risk_score >= 0 AND risk_score <= 100),
  details_json TEXT,
  action TEXT NOT NULL DEFAULT 'log' CHECK(action IN ('log','review','block')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_fraud_events_user ON fraud_events(user_id,created_at);
CREATE INDEX IF NOT EXISTS idx_fraud_events_type ON fraud_events(event_type,created_at);

CREATE TABLE IF NOT EXISTS fraud_settings (
  id INTEGER PRIMARY KEY CHECK(id=1),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  referral_daily_limit INTEGER NOT NULL DEFAULT 20 CHECK(referral_daily_limit > 0),
  referral_same_ip_limit INTEGER NOT NULL DEFAULT 3 CHECK(referral_same_ip_limit > 0),
  max_risk_review INTEGER NOT NULL DEFAULT 50 CHECK(max_risk_review BETWEEN 1 AND 100),
  max_risk_block INTEGER NOT NULL DEFAULT 80 CHECK(max_risk_block BETWEEN 1 AND 100),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO fraud_settings(id) VALUES(1);

CREATE TABLE IF NOT EXISTS user_security (
  user_id INTEGER PRIMARY KEY,
  failed_actions INTEGER NOT NULL DEFAULT 0,
  last_ip_hash TEXT,
  last_user_agent_hash TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS wallet_adjustments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  admin_id INTEGER NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('credit','debit')),
  amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(admin_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_wallet_adjustments_user ON wallet_adjustments(user_id,created_at);

CREATE TABLE IF NOT EXISTS wallet_daily_summary (
  user_id INTEGER NOT NULL,
  summary_date TEXT NOT NULL,
  credits_cents INTEGER NOT NULL DEFAULT 0,
  debits_cents INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(user_id,summary_date),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS withdrawal_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  withdrawal_id INTEGER NOT NULL,
  actor_user_id INTEGER NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('created','approved','rejected','cancelled','refunded')),
  amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
  note TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(withdrawal_id,action),
  FOREIGN KEY(withdrawal_id) REFERENCES withdrawal_requests(id)
);
CREATE INDEX IF NOT EXISTS idx_withdrawal_audit_withdrawal ON withdrawal_audit(withdrawal_id,created_at);

CREATE TABLE IF NOT EXISTS withdrawal_settings (
  id INTEGER PRIMARY KEY CHECK(id=1),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  min_amount_cents INTEGER NOT NULL DEFAULT 1500 CHECK(min_amount_cents > 0),
  max_amount_cents INTEGER NOT NULL DEFAULT 100000 CHECK(max_amount_cents >= min_amount_cents),
  daily_limit_cents INTEGER NOT NULL DEFAULT 100000 CHECK(daily_limit_cents >= max_amount_cents),
  cooldown_minutes INTEGER NOT NULL DEFAULT 10 CHECK(cooldown_minutes >= 0),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO withdrawal_settings(id) VALUES(1);


CREATE TABLE IF NOT EXISTS advertisements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  partner_id INTEGER,
  title TEXT NOT NULL,
  description TEXT,
  image_url TEXT,
  target_url TEXT NOT NULL,
  placement TEXT NOT NULL DEFAULT 'home' CHECK(placement IN ('home','dashboard','missions','ranking','vip')),
  starts_at TEXT,
  ends_at TEXT,
  impressions INTEGER NOT NULL DEFAULT 0,
  clicks INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','archived')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(partner_id) REFERENCES partners(id)
);

CREATE INDEX IF NOT EXISTS idx_ads_status_dates ON advertisements(status,starts_at,ends_at);
CREATE INDEX IF NOT EXISTS idx_ads_partner ON advertisements(partner_id);

CREATE TABLE IF NOT EXISTS ad_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ad_id INTEGER NOT NULL,
  user_id INTEGER,
  event_type TEXT NOT NULL CHECK(event_type IN ('impression','click')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(ad_id) REFERENCES advertisements(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_ad_events_ad ON ad_events(ad_id,created_at);

INSERT OR IGNORE INTO platform_settings(key,value) VALUES
('maintenance_enabled','0'),
('maintenance_message','Sistema em manutenção. Voltaremos em breve.'),
('maintenance_allow_admin','1');

CREATE TABLE IF NOT EXISTS system_health_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  check_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ok','warning','error')),
  details TEXT,
  checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_health_checks_time ON system_health_checks(checked_at);

CREATE INDEX IF NOT EXISTS idx_tickets_status_priority ON tickets(status,priority,last_message_at);
CREATE INDEX IF NOT EXISTS idx_ticket_messages_ticket ON ticket_messages(ticket_id,created_at);

CREATE TABLE IF NOT EXISTS ticket_settings (
  id INTEGER PRIMARY KEY CHECK(id=1),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  max_open_per_user INTEGER NOT NULL DEFAULT 3 CHECK(max_open_per_user > 0),
  cooldown_seconds INTEGER NOT NULL DEFAULT 30 CHECK(cooldown_seconds >= 0),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO ticket_settings(id) VALUES(1);

CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info' CHECK(severity IN ('info','warning','critical')),
  fingerprint TEXT,
  ip_hash TEXT,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_security_events_user_time ON security_events(user_id,created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_type_time ON security_events(event_type,created_at);

CREATE TABLE IF NOT EXISTS security_settings (
  id INTEGER PRIMARY KEY CHECK(id=1),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  max_requests_minute INTEGER NOT NULL DEFAULT 60 CHECK(max_requests_minute > 0),
  max_ticket_messages_minute INTEGER NOT NULL DEFAULT 10 CHECK(max_ticket_messages_minute > 0),
  max_referral_actions_hour INTEGER NOT NULL DEFAULT 20 CHECK(max_referral_actions_hour > 0),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO security_settings(id) VALUES(1);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_time ON audit_logs(actor_user_id,created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_time ON audit_logs(action,created_at);
CREATE INDEX IF NOT EXISTS idx_system_health_checks_status_time ON system_health_checks(status,checked_at);

CREATE TABLE IF NOT EXISTS admin_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL,
  target_user_id INTEGER,
  note TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(admin_id) REFERENCES users(id),
  FOREIGN KEY(target_user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_admin_notes_target ON admin_notes(target_user_id,created_at);
