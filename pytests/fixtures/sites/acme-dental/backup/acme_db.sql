-- MySQL dump 10.13
DROP TABLE IF EXISTS `enquiries`;
CREATE TABLE `enquiries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(120) DEFAULT NULL,
  `email` varchar(150) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `message` text,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
INSERT INTO `enquiries` VALUES (1,'Rahul Private','rahul.private@example.com','9876500000','Need braces price','2025-01-01 10:00:00');
INSERT INTO `enquiries` VALUES (2,'Meena','meena.secret@example.com','9876500001','Whitening?','2025-01-02 11:00:00');
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;
CREATE TABLE `services` (
  `id` int(11) NOT NULL,
  `title` varchar(100) NOT NULL,
  `price` decimal(10,2) DEFAULT NULL
) ENGINE=InnoDB;
