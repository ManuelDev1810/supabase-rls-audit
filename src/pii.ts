import type { PiiColumn } from "./types.ts";

const PEOPLE_TABLE =
  /(user|profile|customer|client|patient|member|employee|staff|contact|lead|student|subscriber|account|person|people|applicant|candidate|driver|guest|tenant|author|seller|buyer)/i;
const MESSAGE_TABLE = /(message|chat|conversation|inbox|dm|thread|ticket|support)/i;

const ALWAYS: Record<string, string> = {
  email: "email", mail: "email", emails: "email",
  phone: "phone", phones: "phone", tel: "phone", telephone: "phone", mobile: "phone", cell: "phone",
  whatsapp: "phone", celular: "phone", telefono: "phone",
  address: "address", addresses: "address", direccion: "address", street: "address",
  zip: "address", zipcode: "address", postal: "address", postcode: "address",
  password: "password", passwd: "password", pwd: "password",
  token: "secret", tokens: "secret", secret: "secret", secrets: "secret", apikey: "secret",
  refresh: "secret", otp: "secret", credential: "secret", credentials: "secret",
  ssn: "government id", dni: "government id", cedula: "government id", passport: "government id",
  rnc: "government id", nit: "government id", curp: "government id", rfc: "government id",
  nif: "government id", cpf: "government id", taxid: "government id",
  card: "financial", iban: "financial", cvv: "financial", routing: "financial",
  balance: "financial", salary: "financial", income: "financial",
  dob: "date of birth", birth: "date of birth", birthday: "date of birth", birthdate: "date of birth",
  ip: "device/location", useragent: "device/location",
  diagnosis: "health", medical: "health", health: "health", prescription: "health", allergies: "health",
};

const PEOPLE_ONLY: Record<string, string> = {
  name: "name", fullname: "name", firstname: "name", lastname: "name", surname: "name",
  nombre: "name", apellido: "name",
  latitude: "device/location", longitude: "device/location", lat: "device/location",
  lng: "device/location", lon: "device/location", geo: "device/location", location: "device/location",
};

const MESSAGE_COLUMNS = new Set(["content", "body", "text", "message", "msg", "transcript"]);

const JOINED_CONTAINS: [string, string][] = [
  ["apikey", "secret"], ["accesskey", "secret"], ["secretkey", "secret"], ["privatekey", "secret"],
  ["accesstoken", "secret"], ["refreshtoken", "secret"], ["passwordhash", "password"], ["passhash", "password"],
  ["cardnumber", "financial"], ["accountnumber", "financial"], ["creditcard", "financial"],
  ["ipaddress", "device/location"], ["useragent", "device/location"], ["dateofbirth", "date of birth"],
  ["taxid", "government id"], ["socialsecurity", "government id"], ["phonenumber", "phone"],
];

export function tokens(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[^A-Za-z0-9]+/g, " ")
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
}

/** Heuristic: which columns look like personal or secret data, given the table name for context. */
export function detectPii(table: string, columns: string[]): PiiColumn[] {
  const people = PEOPLE_TABLE.test(table);
  const messages = MESSAGE_TABLE.test(table);
  const out: PiiColumn[] = [];
  for (const column of columns) {
    const toks = tokens(column);
    const joined = toks.join("");
    let category: string | undefined;
    for (const [needle, cat] of JOINED_CONTAINS) {
      if (joined.includes(needle)) { category = cat; break; }
    }
    if (!category) {
      for (const t of toks) {
        const always = ALWAYS[t];
        if (always) { category = always; break; }
        if (people) {
          const p = PEOPLE_ONLY[t];
          if (p) { category = p; break; }
        }
      }
    }
    if (!category && people) {
      for (let i = 0; i < toks.length - 1; i++) {
        const bigram = PEOPLE_ONLY[`${toks[i]}${toks[i + 1]}`];
        if (bigram) { category = bigram; break; }
      }
    }
    if (!category && messages && MESSAGE_COLUMNS.has(joined)) category = "private content";
    if (category) out.push({ column, category });
  }
  return out;
}
