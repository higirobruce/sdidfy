-- SDID's opaque subject identifier for the citizen, captured at enrolment.
-- NOT the raw NID (which is never stored — Q8); needed for on-demand
-- attribute fetches (/userinfo, spec 04 §4) and periodic re-assertion (Q12).
ALTER TABLE citizens ADD COLUMN sdid_subject text;
CREATE INDEX citizens_sdid_subject_idx ON citizens (sdid_subject);
