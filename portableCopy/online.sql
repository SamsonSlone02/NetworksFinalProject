/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19-11.7.2-MariaDB, for Win64 (AMD64)
--
-- Host: localhost    Database: temp
-- ------------------------------------------------------
-- Server version	11.7.2-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*M!100616 SET @OLD_NOTE_VERBOSITY=@@NOTE_VERBOSITY, NOTE_VERBOSITY=0 */;

--
-- Table structure for table `activeusers`
--

DROP TABLE IF EXISTS `activeusers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `activeusers` (
  `uid` int(11) NOT NULL AUTO_INCREMENT,
  `NFCUID` varchar(30) DEFAULT NULL,
  `name` varchar(30) DEFAULT NULL,
  PRIMARY KEY (`uid`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `activeusers`
--

LOCK TABLES `activeusers` WRITE;
/*!40000 ALTER TABLE `activeusers` DISABLE KEYS */;
INSERT INTO `activeusers` VALUES
(1,'047919eaee6e80','Samson'),
(2,'046064caee6e81','john'),
(5,'040fb0caee6e81','Marco'),
(7,'049640caee6e80','adamWarlock'),
(8,'04de83caee6e80','Venom'),
(10,'1234','Samson!!!');
/*!40000 ALTER TABLE `activeusers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `device_status_log`
--

DROP TABLE IF EXISTS `device_status_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_status_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(60) DEFAULT NULL,
  `ip` varchar(30) DEFAULT NULL,
  `status` enum('online','offline') DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=60 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `device_status_log`
--

LOCK TABLES `device_status_log` WRITE;
/*!40000 ALTER TABLE `device_status_log` DISABLE KEYS */;
INSERT INTO `device_status_log` VALUES
(1,'device 1','100.109.0.40','offline','2025-05-08 04:31:20'),
(4,'device 1','100.109.0.40','offline','2025-05-08 04:33:31'),
(5,' ','100.109.0.40','online','2025-05-08 04:59:57'),
(6,' ','100.109.0.40','offline','2025-05-08 05:05:17'),
(7,' ','100.109.0.40','online','2025-05-08 05:05:57'),
(8,' ','100.109.0.40','offline','2025-05-08 05:59:30'),
(9,' ','100.109.0.40','online','2025-05-08 05:59:50'),
(10,' ','100.109.0.40','offline','2025-05-08 06:02:41'),
(11,' ','100.109.0.40','online','2025-05-08 06:18:20'),
(12,' ','100.109.0.40','offline','2025-05-08 06:30:41'),
(36,'','100.109.0.40','online','2025-05-08 18:44:50'),
(37,'','100.109.0.40','offline','2025-05-08 18:45:53'),
(38,'','100.109.0.40','online','2025-05-08 18:46:03'),
(39,'','100.109.0.40','offline','2025-05-08 18:53:35'),
(40,'','100.116.50.70','online','2025-05-08 18:54:05'),
(41,'','100.116.50.70','offline','2025-05-08 18:54:35'),
(42,'','100.109.0.40','online','2025-05-08 18:56:15'),
(43,'','100.109.0.40','offline','2025-05-08 19:26:26'),
(44,'','100.109.0.40','online','2025-05-08 20:28:50'),
(45,'','100.109.0.40','offline','2025-05-08 20:45:41'),
(46,'','100.109.0.40','online','2025-05-08 21:16:12'),
(47,'','100.109.0.40','offline','2025-05-08 22:09:25'),
(48,'','100.109.0.40','online','2025-05-08 22:44:27'),
(49,'','100.109.0.40','offline','2025-05-08 22:57:08'),
(50,'','100.116.50.70','online','2025-05-08 23:29:23'),
(51,'','100.109.0.40','online','2025-05-08 23:29:43'),
(52,'','100.116.50.70','offline','2025-05-08 23:30:13'),
(53,'','100.109.0.40','offline','2025-05-08 23:52:14'),
(54,'','100.116.50.70','online','2025-05-09 00:02:05'),
(55,'','100.116.50.70','offline','2025-05-09 00:02:25'),
(56,'','100.109.0.40','online','2025-05-09 00:26:46'),
(57,'','100.116.50.70','online','2025-05-09 00:26:56'),
(58,'','100.116.50.70','offline','2025-05-09 00:28:26'),
(59,'','100.109.0.40','offline','2025-05-09 00:35:26');
/*!40000 ALTER TABLE `device_status_log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `logins`
--

DROP TABLE IF EXISTS `logins`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `logins` (
  `loginTime` timestamp NULL DEFAULT current_timestamp(),
  `lid` int(11) NOT NULL AUTO_INCREMENT,
  `uid` int(11) DEFAULT NULL,
  PRIMARY KEY (`lid`),
  KEY `uid` (`uid`),
  CONSTRAINT `logins_ibfk_1` FOREIGN KEY (`uid`) REFERENCES `activeusers` (`uid`)
) ENGINE=InnoDB AUTO_INCREMENT=151 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `logins`
--

LOCK TABLES `logins` WRITE;
/*!40000 ALTER TABLE `logins` DISABLE KEYS */;
INSERT INTO `logins` VALUES
('2025-05-08 22:44:37',132,1),
('2025-05-08 22:44:41',133,8),
('2025-05-08 22:44:47',134,7),
('2025-05-08 23:24:41',135,2),
('2025-05-08 23:25:06',136,7),
('2025-05-09 00:27:44',137,2),
('2025-05-09 07:28:20',138,8),
('2025-05-09 07:28:23',139,2),
('2025-05-09 07:28:29',140,7),
('2025-05-09 00:28:20',141,8),
('2025-05-09 00:28:23',142,2),
('2025-05-09 00:28:29',143,7),
('2025-05-15 23:16:23',149,10),
('2025-05-16 06:16:52',150,10);
/*!40000 ALTER TABLE `logins` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*M!100616 SET NOTE_VERBOSITY=@OLD_NOTE_VERBOSITY */;

-- Dump completed on 2025-05-15 16:19:08
