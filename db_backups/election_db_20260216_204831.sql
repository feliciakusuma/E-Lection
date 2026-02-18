--
-- PostgreSQL database dump
--

\restrict 7SGW8fqFeMpx2jJW3sxqjUlEtB2dmNavj6lIfKOODy9roS3cUcbh4bRUxNoK4a4

-- Dumped from database version 18.1
-- Dumped by pg_dump version 18.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: admins; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.admins (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    full_name character varying(200) NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    status character varying(20),
    verification_token character varying(100),
    is_active boolean,
    created_at timestamp without time zone NOT NULL
);


ALTER TABLE public.admins OWNER TO postgres;

--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.audit_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    table_name character varying(50) NOT NULL,
    record_id uuid NOT NULL,
    action character varying(50) NOT NULL,
    user_id character varying(100),
    ip_address character varying(45),
    user_agent character varying(500),
    "timestamp" timestamp without time zone NOT NULL,
    is_authorized boolean
);


ALTER TABLE public.audit_logs OWNER TO postgres;

--
-- Name: candidate_tickets; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.candidate_tickets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    election_id uuid NOT NULL,
    president_candidate_id uuid NOT NULL,
    vice_president_candidate_id uuid,
    created_at timestamp without time zone NOT NULL
);


ALTER TABLE public.candidate_tickets OWNER TO postgres;

--
-- Name: candidates; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.candidates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    full_name character varying(100) NOT NULL,
    student_id character varying(20) NOT NULL,
    cohort_id uuid,
    major_id uuid,
    "position" character varying(100) NOT NULL,
    status character varying(20),
    is_active boolean,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone
);


ALTER TABLE public.candidates OWNER TO postgres;

--
-- Name: cohort; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.cohort (
    cohort_id uuid DEFAULT gen_random_uuid() NOT NULL,
    cohort_num integer NOT NULL
);


ALTER TABLE public.cohort OWNER TO postgres;

--
-- Name: elections; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.elections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    title character varying(200) NOT NULL,
    description text,
    start_date timestamp without time zone NOT NULL,
    end_date timestamp without time zone NOT NULL,
    status character varying(20),
    is_active boolean,
    results_json text,
    created_at timestamp without time zone NOT NULL
);


ALTER TABLE public.elections OWNER TO postgres;

--
-- Name: majors; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.majors (
    major_id uuid DEFAULT gen_random_uuid() NOT NULL,
    major_code integer NOT NULL,
    major_name character varying(200) NOT NULL
);


ALTER TABLE public.majors OWNER TO postgres;

--
-- Name: system_config; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.system_config (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key character varying(100) NOT NULL,
    value text NOT NULL,
    is_readonly boolean,
    created_at timestamp without time zone NOT NULL
);


ALTER TABLE public.system_config OWNER TO postgres;

--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    first_name character varying(100) NOT NULL,
    last_name character varying(100) NOT NULL,
    email character varying(255) NOT NULL,
    student_id character varying(50) NOT NULL,
    cohort_id uuid,
    major_id uuid,
    status character varying(20),
    verification_token_encrypted text,
    is_active boolean,
    created_at timestamp without time zone NOT NULL,
    verification_token_hash character varying(64),
    verification_token character varying(100)
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Name: voter_election_status; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.voter_election_status (
    voter_id character varying(100) NOT NULL,
    election_id uuid NOT NULL,
    has_voted boolean NOT NULL,
    created_at timestamp without time zone NOT NULL
);


ALTER TABLE public.voter_election_status OWNER TO postgres;

--
-- Name: votes; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.votes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    election_id uuid NOT NULL,
    vote_encrypted bytea NOT NULL,
    vote_nonce bytea NOT NULL,
    verification_code character varying(100) NOT NULL,
    is_counted boolean,
    created_at timestamp without time zone NOT NULL
);


ALTER TABLE public.votes OWNER TO postgres;

--
-- Data for Name: admins; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.admins (id, full_name, email, password_hash, status, verification_token, is_active, created_at) FROM stdin;
eb096d9c-e580-4b2c-b9ed-00e54cc31a12	Felicia Kusuma	felicia.kusuma294@gmail.com	$2b$12$5w8LaMeinKXG5VsEr3u1cuOeyu1njV5QgamnR/.fO33HPj40IKkEW	active	bmulI9zeB_-ViZpZM3FQT9Uu3kXBGvfliphtuxpCguQ	t	2025-12-22 12:17:19.751256
\.


--
-- Data for Name: audit_logs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.audit_logs (id, table_name, record_id, action, user_id, ip_address, user_agent, "timestamp", is_authorized) FROM stdin;
8ec543a1-8d0b-4778-8ff3-246397aa8bfa	users	0506171b-5ff1-46e4-86db-9a921e8d12f3	REGISTRATION_SUCCESS	felicia.kusuma294@gmail.com	127.0.0.1	\N	2025-12-22 12:19:12.921117	t
9e3f8a18-a3c8-4452-bdf2-ac28e1798999	users	f322a9d5-c0a7-4bdd-8ab4-b1ae97a6703c	REGISTRATION_SUCCESS	felicia.kusuma294@gmail.com	127.0.0.1	\N	2025-12-22 12:22:05.266581	t
fae14c8d-af67-4626-afe3-5fc8ae1eb5a0	users	f322a9d5-c0a7-4bdd-8ab4-b1ae97a6703c	LOGIN_GOOGLE_SUCCESS	f322a9d5-c0a7-4bdd-8ab4-b1ae97a6703c	127.0.0.1	\N	2025-12-22 12:23:06.759134	t
fcb101d1-fcf6-41e2-8b42-5c4431faa9ea	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	127.0.0.1	\N	2025-12-22 12:23:21.606298	t
102fad95-da92-43ea-b08b-185ef3509643	votes	ab04e51c-cd93-4c5b-ab29-0baa891f1bf1	VOTE_CAST	felicia.kusuma294@gmail.com	127.0.0.1	\N	2025-12-22 15:53:11.376499	t
68a0a7ec-85c0-493c-8295-221f4573436b	votes	347a35fe-9a70-482a-9039-49754546d901	VOTE_CAST	felicia.kusuma294@gmail.com	127.0.0.1	\N	2025-12-22 16:03:35.861722	t
67faa050-0f3a-4d07-b38e-ff67feb3de9d	votes	0f3249ed-e033-4c73-a870-f1d1d44af4ad	VOTE_CAST	felicia.kusuma294@gmail.com	127.0.0.1	\N	2025-12-22 16:18:44.796475	t
296f1d32-5a84-4184-bee2-9998670c173b	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	127.0.0.1	\N	2026-01-30 14:39:40.690856	t
9be02f46-bb77-4120-9cec-d8dcfd2100c6	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	127.0.0.1	\N	2026-02-04 08:45:47.167003	t
2504920c-d8b5-404d-ae66-f7cf4edfd323	users	42bcf9cd-95fc-420d-a137-c32f0d2d54cc	REGISTRATION_SUCCESS	felicia.kusuma@my.sampoernauniversity.ac.id	127.0.0.1	\N	2026-02-04 10:03:57.757889	t
1b5da9c2-4300-4613-9172-5e34dc4d4f82	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	REGISTRATION_SUCCESS	felicia.kusuma@my.sampoernauniversity.ac.id	127.0.0.1	\N	2026-02-04 10:06:03.187695	t
e8ff99eb-be57-410b-8c34-6a7c7c7ab7a9	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-04 13:48:50.35807	t
8093bb15-a722-4523-b07e-69c4646bd4a7	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-04 14:47:30.008925	t
45958295-8d43-4f5f-9028-7cf4daf8ea4a	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-04 15:12:35.570656	t
4e88de3b-dc3a-45d7-839a-f4b8f69acbc0	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-04 15:33:51.354836	t
71d7bf72-da0a-494e-904c-30dc629d82dd	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-04 15:43:26.349764	t
488039e4-236c-4568-94d1-f4d3b242e6b1	votes	52a6a1c2-c65a-4ad5-b690-70c15dfc774e	VOTE_CAST	felicia.kusuma@my.sampoernauniversity.ac.id	::1	\N	2026-02-04 16:14:29.57493	t
463f32c6-0b18-46bc-9644-ae7e309ff739	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-04 16:14:53.477182	t
ce25118c-9735-487c-bad0-549ad0aec9bb	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-04 16:27:22.51285	t
1b3476bd-2dae-4122-8314-16ae41fc95a7	votes	8a1dee74-dca1-4279-9da8-857ee9d5485f	VOTE_CAST	felicia.kusuma@my.sampoernauniversity.ac.id	::1	\N	2026-02-04 16:28:24.958895	t
703e9cc9-4bbe-4f49-b98d-1a092d93bc4e	votes	632aac49-ebd8-4d71-a24a-ae8c4523d66a	VOTE_CAST	felicia.kusuma@my.sampoernauniversity.ac.id	::1	\N	2026-02-04 16:38:24.861199	t
cc083bef-bbcd-44ac-b415-06b5b2f93c1a	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-04 16:38:36.174249	t
ecb23e17-1eb3-422a-891e-edf940a29c29	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-04 16:44:29.045227	t
4709df76-3111-4ca7-ac52-1fd1a5f8c10b	votes	f70e0c35-9e23-4280-b5c1-a91b8cf314ed	VOTE_CAST	felicia.kusuma@my.sampoernauniversity.ac.id	::1	\N	2026-02-04 16:44:34.790608	t
b1250e2e-2298-4df5-821b-5b7ce062d9e2	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-04 16:45:58.503224	t
500ebe6e-4d2d-4e2d-8e05-57df3a0d7128	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-04 16:46:23.843649	t
1cd887e1-44bc-492b-8c2f-37265c97bfdb	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-05 06:02:04.49169	t
dc5b0b95-dca5-4ac2-9ab7-c5a25d677550	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-05 06:03:19.20183	t
9e3525dd-232e-4ce8-8f05-0b0c588eef5a	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-05 06:05:42.829107	t
758917de-3cc8-4b49-8845-c4c45ebeb64d	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-05 06:05:48.745529	t
f40d1d10-7e59-4654-88e8-ee23900a1897	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-05 06:06:32.369259	t
707ce0a8-c475-4892-826c-894db1b39786	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-05 06:06:50.43459	t
06d1f307-8fa2-4dac-b7c1-c42a49feda13	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-05 06:07:36.076668	t
f5f5f2ea-4c34-4783-9507-8e7ba6d288e2	votes	997bf71f-089d-42ce-b6da-e77d6cbef5cf	VOTE_CAST	felicia.kusuma@my.sampoernauniversity.ac.id	::1	\N	2026-02-05 06:07:42.76693	t
4ea35128-552b-4293-b6fb-222562b22930	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-05 06:07:59.610136	t
cf650e9f-d99a-48ad-a380-f31e1998a709	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-05 09:06:08.626358	t
32ae1393-05d5-459f-a094-d8105cbe8975	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-05 09:07:01.203161	t
b6b6e6be-1a5c-4d95-8f50-802d0dd59635	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-09 09:38:13.070898	t
914db3a5-435b-4123-9d74-34deebafec37	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-09 14:58:39.18394	t
2441f513-72ba-4a1b-9c85-2548cf43aa6a	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-09 15:07:57.970104	t
34e24f99-3888-4bd0-99ed-e72f7c784969	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-09 15:27:41.441561	t
04f3e497-4e97-485f-bac1-1798e405f733	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-16 12:05:23.533287	t
817723e0-6132-4233-961e-bb206f42a98b	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-16 12:07:01.91054	t
a7e52933-fd67-4898-9df1-1a21b99240f5	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-16 12:16:21.329655	t
2cca8e52-2aa8-4b60-b8fa-130297f5d09c	admins	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	ADMIN_LOGIN_SUCCESS	eb096d9c-e580-4b2c-b9ed-00e54cc31a12	::1	\N	2026-02-16 12:25:24.287352	t
3ebef39e-487a-4d74-ae3f-14201e802930	users	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	LOGIN_MICROSOFT_SUCCESS	dca86f9c-c53f-4fe3-83e5-247e4729eb1e	::1	\N	2026-02-16 12:26:40.439044	t
9ef6fdf2-12dd-4c4f-a9c2-05172305dff0	votes	3c33a3f6-dbe7-4e48-9ce3-849e8ff89c5a	VOTE_CAST	felicia.kusuma@my.sampoernauniversity.ac.id	::1	\N	2026-02-16 12:27:45.178845	t
\.


--
-- Data for Name: candidate_tickets; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.candidate_tickets (id, election_id, president_candidate_id, vice_president_candidate_id, created_at) FROM stdin;
03799a02-739e-4d9a-8b8d-476ff2624efc	04babc75-acbf-4f46-99b8-18a5a580ce93	cef17534-467f-496c-831f-59ede355bd9a	4d8da443-fdc8-4228-abff-5d22d6f655cf	2026-02-04 14:47:51.707494
06ab1f89-2c38-45ca-8811-2c5cd6377c0e	04babc75-acbf-4f46-99b8-18a5a580ce93	40c3a3d6-8438-47a1-ab60-00609ac70f37	e845a499-074a-434a-af42-a61df2809c17	2026-02-04 15:42:16.011066
4275b900-5fa8-4805-867b-b341f8d3814a	2113702f-864f-43fc-8271-42d6fa8c4288	229f7879-bccd-4a38-a592-ee5316e9157b	\N	2026-02-05 06:03:51.566355
3b6fe675-8fc5-43c9-af5f-59038afbfb57	2113702f-864f-43fc-8271-42d6fa8c4288	ae018fd9-f58d-4bed-b9ca-2bd6298128f3	\N	2026-02-05 06:04:11.195668
278172e7-3bb2-45af-8735-701782a5babe	2113702f-864f-43fc-8271-42d6fa8c4288	4cbd9a32-af5e-44c7-9daa-c750592df20b	\N	2026-02-05 06:04:53.762254
418a4e28-a4d2-4dff-ba69-9e1d16eec25f	2113702f-864f-43fc-8271-42d6fa8c4288	5293720a-b1bf-42c6-8249-420a3d268d91	\N	2026-02-09 15:28:03.891571
\.


--
-- Data for Name: candidates; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.candidates (id, full_name, student_id, cohort_id, major_id, "position", status, is_active, created_at, updated_at) FROM stdin;
cef17534-467f-496c-831f-59ede355bd9a	Fel	2022400005	e1180642-df02-4ad1-8975-3e0634b94bb0	64ae2007-cfe6-47fc-99b4-f20bb016da19	1	running	t	2026-02-04 14:47:51.705012	2026-02-04 15:42:26.78672
4d8da443-fdc8-4228-abff-5d22d6f655cf	Mel	2022400013	e1180642-df02-4ad1-8975-3e0634b94bb0	64ae2007-cfe6-47fc-99b4-f20bb016da19	1	running	t	2026-02-04 15:42:26.792482	2026-02-04 15:42:26.792477
40c3a3d6-8438-47a1-ab60-00609ac70f37	Kat	2022400017	e1180642-df02-4ad1-8975-3e0634b94bb0	64ae2007-cfe6-47fc-99b4-f20bb016da19	1	running	t	2026-02-04 15:42:16.009868	2026-02-04 15:43:01.317757
e845a499-074a-434a-af42-a61df2809c17	Ferry	2022400010	e1180642-df02-4ad1-8975-3e0634b94bb0	64ae2007-cfe6-47fc-99b4-f20bb016da19	1	running	t	2026-02-04 15:42:32.024317	2026-02-04 15:43:01.320354
4cbd9a32-af5e-44c7-9daa-c750592df20b	Dafi 	2023510002	ccb33c87-dabb-45aa-a230-8088781f61e0	e355583c-7ab0-4328-9029-2149003b34e4	2	running	t	2026-02-05 06:04:53.760492	2026-02-05 06:05:07.075715
229f7879-bccd-4a38-a592-ee5316e9157b	Verrel	2023510009	ccb33c87-dabb-45aa-a230-8088781f61e0	e355583c-7ab0-4328-9029-2149003b34e4	2	running	t	2026-02-05 06:03:51.566355	2026-02-05 06:07:16.620532
\.


--
-- Data for Name: cohort; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.cohort (cohort_id, cohort_num) FROM stdin;
afe85059-5b0c-4852-a5f2-ec3a224f26b5	2024
355cc532-cb2b-4766-9765-f2c4ea5a54da	2025
589df74f-3f2f-4771-851b-161e2806fc19	2022
a4b59cf9-8838-4bc2-a5ec-fe63fd19606d	2023
\.


--
-- Data for Name: elections; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.elections (id, title, description, start_date, end_date, status, is_active, results_json, created_at) FROM stdin;
04babc75-acbf-4f46-99b8-18a5a580ce93	1	{"major": "All Majors", "cohort": "2022,2023,2024", "tz_offset_minutes": 420, "eligible_voters": 10}	2026-02-04 09:42:00	2026-02-12 09:42:00	ongoing	t	\N	2026-02-04 09:43:03.809287
2113702f-864f-43fc-8271-42d6fa8c4288	2	{"major": "All Majors", "cohort": "All Cohort", "tz_offset_minutes": 420, "eligible_voters": 30}	2026-02-05 06:05:00	2026-02-26 09:45:00	ongoing	t	\N	2026-02-04 09:45:44.200985
\.


--
-- Data for Name: majors; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.majors (major_id, major_code, major_name) FROM stdin;
b39f6d3f-351f-4d3f-ae2b-79f4adb8cf4b	22	Management
7612ba4f-ba5c-4c7f-bbf4-7d6f49097342	37	Industrial Engineering
2de1f452-057f-40d9-893f-01e9b37e9103	39	Computer Science
489fee08-bfd4-47de-b63a-d141a3d8c403	40	Information Systems
4679c3f2-095b-4ee7-bd4b-ff2ee916a2db	21	Accounting
f319f0f4-45a7-419f-b25c-ed577881cd4e	51	Psychology
4c8f5193-9fe6-4593-a625-690fdd736dc0	36	Mechanical Engineering
5d848586-cf69-432c-9ff9-bdc8d7a28f93	41	Visual Communication Design
a9684dd2-5a04-4794-968e-d14ca4605040	12	English Education
\.


--
-- Data for Name: system_config; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.system_config (id, key, value, is_readonly, created_at) FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.users (id, first_name, last_name, email, student_id, cohort_id, major_id, status, verification_token_encrypted, is_active, created_at, verification_token_hash, verification_token) FROM stdin;
dca86f9c-c53f-4fe3-83e5-247e4729eb1e	Felicia	Kusuma	felicia.kusuma@my.sampoernauniversity.ac.id	2022400005	95760d43-c5c9-4d63-a12e-15a82ee8f17a	3a55ec9f-1704-417c-90cc-6be551135c77	verified	gAAAAABpgxoIfruR2tEDSVz-S-sxhjAuH5ZfPULodduBj1ZqOZrRewfcq1DE-y4EVqNElSglrDDwEaPAK9N4nCN5ZVlk7eWwsQ==	t	2026-02-04 10:06:00.270494	fb1e749c52c4b9ab16a45690feba0299d68de40f459efc01c0992cd016b1e8cb	\N
\.


--
-- Data for Name: voter_election_status; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.voter_election_status (voter_id, election_id, has_voted, created_at) FROM stdin;
f322a9d5-c0a7-4bdd-8ab4-b1ae97a6703c	d8b262e8-3d1e-443a-a44b-296d79b18381	f	2025-12-22 15:53:11.366062
f322a9d5-c0a7-4bdd-8ab4-b1ae97a6703c	08a63992-c30c-4ffb-8fdc-daf95a544082	f	2025-12-22 16:18:44.78769
dca86f9c-c53f-4fe3-83e5-247e4729eb1e	04babc75-acbf-4f46-99b8-18a5a580ce93	t	2026-02-04 16:14:29.564809
dca86f9c-c53f-4fe3-83e5-247e4729eb1e	2113702f-864f-43fc-8271-42d6fa8c4288	t	2026-02-05 06:07:42.752407
\.


--
-- Data for Name: votes; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.votes (id, election_id, vote_encrypted, vote_nonce, verification_code, is_counted, created_at) FROM stdin;
f70e0c35-9e23-4280-b5c1-a91b8cf314ed	04babc75-acbf-4f46-99b8-18a5a580ce93	\\xd8ec425a0a8741e30518982676755623532f8433b0ec2e7fd6120c5eca6faabc22ec465e79dac6471d8a688ff747dc26d916307efaa3dec70bf64d092fb0c39464cf97fcede9a5114b95ed95f5232ca34b79dc2abd510aaab75cb6b00b32c5725df58bb1836d8fb68ae8ede8ceda294d15998a958546d6e6907579fbbfad771894496f4d891a228cdfef3a5099db73beb443b6e8323b258db120c163db6b162e3d265ca1982706d178be2a8e36a434664176025191f0e1ad1b22319bfcc7b679367c27dffa008dd8cc9bc9511b7680e5013a6d64fac7994e915610	\\x732be0f9ac0cede28e2ff3a3	RaeznNFl_U4GFxjTNIpFODOmJSu2-o8zpV7Y9r4S5T0	t	2026-02-04 16:44:34.785552
3c33a3f6-dbe7-4e48-9ce3-849e8ff89c5a	2113702f-864f-43fc-8271-42d6fa8c4288	\\x7496974e77b56233494548ab8d6ffd77b2195cb7cea92d817b05e385d7fb01c6c5dbd0fd53f7032da471a6c0d0b6edaddbbfb42a810752f3058953fc742fb03a999e1b8fb3f29104df82a4aaf84038babd23c330084ea8bcdb4140280c00f9c20c6d3c2a0e4432f068fb0746ef5f6086140ddab25e25bdf40860aa7abae82154c8f6af364a3cf4a5bd48ae5294a7030059ad1181d46a9401c023ec1f35914c49b0b14dabd7bdc64168e1a19a7d54f9d9fb9b02776e8c23acb13be27f8a50f31f256e6355c60f2374e53aa32170fdf36e518bd39476c82450a58d72	\\x942e4b4b8710a8a8f8017c68	M6C3aRv4jN8nYKSm02vK0vPC8RYdU6s6eYxwMShfIuc	t	2026-02-16 12:27:45.172846
\.


--
-- Name: admins admins_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_pkey PRIMARY KEY (id);


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: candidate_tickets candidate_tickets_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.candidate_tickets
    ADD CONSTRAINT candidate_tickets_pkey PRIMARY KEY (id);


--
-- Name: candidates candidates_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.candidates
    ADD CONSTRAINT candidates_pkey PRIMARY KEY (id);


--
-- Name: cohort cohort_cohort_num_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cohort
    ADD CONSTRAINT cohort_cohort_num_key UNIQUE (cohort_num);


--
-- Name: cohort cohort_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cohort
    ADD CONSTRAINT cohort_pkey PRIMARY KEY (cohort_id);


--
-- Name: elections elections_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.elections
    ADD CONSTRAINT elections_pkey PRIMARY KEY (id);


--
-- Name: majors majors_major_code_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.majors
    ADD CONSTRAINT majors_major_code_key UNIQUE (major_code);


--
-- Name: majors majors_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.majors
    ADD CONSTRAINT majors_pkey PRIMARY KEY (major_id);


--
-- Name: system_config system_config_key_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.system_config
    ADD CONSTRAINT system_config_key_key UNIQUE (key);


--
-- Name: system_config system_config_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.system_config
    ADD CONSTRAINT system_config_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_student_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_student_id_key UNIQUE (student_id);


--
-- Name: voter_election_status voter_election_status_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.voter_election_status
    ADD CONSTRAINT voter_election_status_pkey PRIMARY KEY (voter_id, election_id);


--
-- Name: votes votes_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.votes
    ADD CONSTRAINT votes_pkey PRIMARY KEY (id);


--
-- Name: votes votes_verification_code_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.votes
    ADD CONSTRAINT votes_verification_code_key UNIQUE (verification_code);


--
-- Name: ix_admins_email; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX ix_admins_email ON public.admins USING btree (email);


--
-- Name: ix_admins_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_admins_id ON public.admins USING btree (id);


--
-- Name: ix_audit_logs_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_audit_logs_id ON public.audit_logs USING btree (id);


--
-- Name: ix_candidate_tickets_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_candidate_tickets_id ON public.candidate_tickets USING btree (id);


--
-- Name: ix_candidates_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_candidates_id ON public.candidates USING btree (id);


--
-- Name: ix_elections_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_elections_id ON public.elections USING btree (id);


--
-- Name: ix_system_config_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_system_config_id ON public.system_config USING btree (id);


--
-- Name: ix_users_email; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX ix_users_email ON public.users USING btree (email);


--
-- Name: ix_users_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_users_id ON public.users USING btree (id);


--
-- Name: ix_users_verification_token_hash; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_users_verification_token_hash ON public.users USING btree (verification_token_hash);


--
-- Name: ix_votes_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_votes_id ON public.votes USING btree (id);


--
-- PostgreSQL database dump complete
--

\unrestrict 7SGW8fqFeMpx2jJW3sxqjUlEtB2dmNavj6lIfKOODy9roS3cUcbh4bRUxNoK4a4

