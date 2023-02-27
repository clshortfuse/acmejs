import { decodeDER, readLength, readObjectIdentifier, readSignedNumber, readUnsignedNumber, writeLength, writeSignedNumber, writeUnsignedNumber } from '../../utils/asn1.js';
import { derFromPEM } from '../../utils/certificate.js';
import test from '../tester.js';

test('writeUnsignedNumber()', (t) => {
  t.deepEqual(writeUnsignedNumber(1), [1]);
  t.deepEqual(writeUnsignedNumber(0), [0]);
  t.deepEqual(writeUnsignedNumber(50), [0b0011_0010]);
  t.deepEqual(writeUnsignedNumber(156), [0b1001_1100]);
  t.deepEqual(writeUnsignedNumber(127), [127]);
  t.deepEqual(writeUnsignedNumber(128), [128]);
  t.deepEqual(writeUnsignedNumber(255), [255]);
  t.deepEqual(writeUnsignedNumber((2n ** 63n) + 1n), [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
});

test('readUnsignedNumber()', (t) => {
  t.deepEqual(readUnsignedNumber([1]), 1);
  t.deepEqual(readUnsignedNumber([0]), 0);
  t.deepEqual(readUnsignedNumber([0b0011_0010]), 50);
  t.deepEqual(readUnsignedNumber([0b1001_1100]), 156);
  t.deepEqual(readUnsignedNumber([127]), 127);
  t.deepEqual(readUnsignedNumber([128]), 128);
  t.deepEqual(readUnsignedNumber([255]), 255);
  t.deepEqual(readUnsignedNumber([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]), (2n ** 63n) + 1n);
});

test('writeSignedNumber()', (t) => {
  t.deepEqual(writeSignedNumber(1), [1]);
  t.deepEqual(writeSignedNumber(0), [0]);
  t.deepEqual(writeSignedNumber(50), [0b0011_0010]);
  t.deepEqual(writeSignedNumber(-100), [0b1001_1100]);
  t.deepEqual(writeSignedNumber(-549_755_813_887), [0b1000_0000, 0b0000_0000, 0b0000_0000, 0b0000_0000, 0b0000_0001]);
  t.deepEqual(writeSignedNumber(127), [127]);
  t.deepEqual(writeSignedNumber(128), [0x00, 128]);
  t.deepEqual(writeSignedNumber(255), [0x00, 255]);
  t.deepEqual(writeSignedNumber((2n ** 63n) + 1n), [0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
});

test('readSignedNumber()', (t) => {
  t.deepEqual(readSignedNumber([1]), 1);
  t.deepEqual(readSignedNumber([0]), 0);
  t.deepEqual(readSignedNumber([0b0011_0010]), 50);
  t.deepEqual(readSignedNumber([0b1001_1100]), -100);
  t.deepEqual(readSignedNumber([0b1000_0000, 0b0000_0000, 0b0000_0000, 0b0000_0000, 0b0000_0001]), -549_755_813_887);
  t.deepEqual(readSignedNumber([127]), 127);
  t.deepEqual(readSignedNumber([0x00, 128]), 128);
  t.deepEqual(readSignedNumber([0x00, 255]), 255);
  t.deepEqual(readSignedNumber([0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]), (2n ** 63n) + 1n);
});

test('writeLength()', (t) => {
  t.deepEqual(writeLength(1), [1]);
  t.deepEqual(writeLength(0), [0]);
  t.deepEqual(writeLength(127), [127]);
  t.deepEqual(writeLength(null), [128]); // Indefinite
  t.deepEqual(writeLength(128), [128 + 1, 128]);
  t.deepEqual(writeLength(129), [128 + 1, 129]);
  t.deepEqual(writeLength(130), [128 + 1, 130]);
  t.deepEqual(writeLength(0xF_FF), [128 + 2, 0xF, 0xFF]);
  t.deepEqual(writeLength(0xFF_FF), [128 + 2, 0xFF, 0xFF]);
  t.deepEqual(writeLength(0xFF_FF + 1), [128 + 3, 1, 0, 0]);
  t.deepEqual(writeLength(0xF_FF_FF), [128 + 3, 0xF, 0xFF, 0xFF]);
  t.deepEqual(writeLength(0xFF_FF_FF), [128 + 3, 0xFF, 0xFF, 0xFF]);
  t.deepEqual(writeLength(0xFF_FF_FF + 1), [128 + 4, 1, 0, 0, 0]);
  t.deepEqual(writeLength(0xFF_FF_FF_FF), [128 + 4, 0xFF, 0xFF, 0xFF, 0xFF]);
  t.deepEqual(writeLength(0xFF_FF_FF_FF + 1), [128 + 5, 1, 0, 0, 0, 0]);
  t.deepEqual(writeLength(0xFF_FF_FF_FF_FF_FF), [128 + 6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
  t.deepEqual(writeLength(0x1F_FF_FF_FF_FF_FF_FF), [128 + 7, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
});

test('readLength()', (t) => {
  t.deepEqual(readLength([1]), { length: 1, bytesRead: 1 });
  t.deepEqual(readLength([0]), { length: 0, bytesRead: 1 });
  t.deepEqual(readLength([127]), { length: 127, bytesRead: 1 });
  t.deepEqual(readLength([128]), { length: null, bytesRead: 1 });
  t.deepEqual(readLength([128 + 1, 128]), { length: 128, bytesRead: 2 });
  t.deepEqual(readLength([128 + 1, 129]), { length: 129, bytesRead: 2 });
  t.deepEqual(readLength([128 + 1, 130]), { length: 130, bytesRead: 2 });
  t.deepEqual(readLength([128 + 2, 0xF, 0xFF]), { length: 0xF_FF, bytesRead: 3 });
  t.deepEqual(readLength([128 + 2, 0xFF, 0xFF]), { length: 0xFF_FF, bytesRead: 3 });
  t.deepEqual(readLength([128 + 3, 1, 0, 0]), { length: 0xFF_FF + 1, bytesRead: 4 });
  t.deepEqual(readLength([128 + 3, 0xF, 0xFF, 0xFF]), { length: 0xF_FF_FF, bytesRead: 4 });
  t.deepEqual(readLength([128 + 3, 0xFF, 0xFF, 0xFF]), { length: 0xFF_FF_FF, bytesRead: 4 });
  t.deepEqual(readLength([128 + 4, 1, 0, 0, 0]), { length: 0xFF_FF_FF + 1, bytesRead: 5 });
  t.deepEqual(readLength([128 + 4, 0xFF, 0xFF, 0xFF, 0xFF]), { length: 0xFF_FF_FF_FF, bytesRead: 5 });
  t.deepEqual(readLength([128 + 5, 1, 0, 0, 0, 0]), { length: 0xFF_FF_FF_FF + 1, bytesRead: 6 });
  t.deepEqual(readLength([128 + 6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), { length: 0xFF_FF_FF_FF_FF_FF, bytesRead: 7 });
  t.deepEqual(
    readLength([128 + 7, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
    { length: 0x1F_FF_FF_FF_FF_FF_FF, bytesRead: 8 },
  );
});

test('readObjectIdentifier()', (t) => {
  t.deepEqual(readObjectIdentifier([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]), '1.2.840.113549.1.1.11');
});

test('decodeDER()', (t) => {
  const data = `-----BEGIN PRIVATE KEY-----
  MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDD0tPV/du2vftjvXj1t/gXTK39
  sNBVrOAEb/jKzXae+Xa0H+3LhZaQIQNMfACiBSgIfZUvEGb+7TqXWQpoLoFR/R7MvGWcSk98JyrV
  tveD8ZmZYyItSY7m2hcasqAFiKyOouV5vzyRe87/lEyzzBpF3bQQ4IDaQu+K9Hj5fKuU6rrOeOhs
  dnJc+VdDQLScHxvMoLZ9Vtt+oK9J4/tOLwr4CG8khDlBURcBY6gPcLo3dPU09SW+6ctX2cX4mkXx
  6O/0mmdTmacr/vu50KdRMleFeZYOWPAEhhMfywybTuzBiPVIZVP8WFCSKNMbfi1S9A9PdBqnebww
  HhX3/hsEBt2BAgMBAAECggEABEI1P6nf6Zs7mJlyBDv+Pfl5rjL2cOqLy6TovvZVblMkCPpJyFuN
  IPDK2tK2i897ZaXfhPDBIKmllM2Hq6jZQKB110OAnTPDg0JxzMiIHPs32S1d/KilHjGff4Hjd4NX
  p1l1Dp8BUPOllorR2TYm2x6dcCGFw9lhTr8O03Qp4hjn84VjGIWADYCk83mgS4nRsnHkdiqYnWx1
  AjKlY51yEK6RcrDMi0Th2RXrrINoC35sVv+APt2rkoMGi52RwTEseA1KZGFrxjq61ReJif6p2VXE
  cvHeX6CWLx014LGk43z6Q28P6HgeEVEfIjyqCUea5Du/mYb/QsRSCosXLxBqwQKBgQD1+fdC9ZiM
  rVI+km7Nx2CKBn8rJrDmUh5SbXn2MYJdrUd8bYNnZkCgKMgxVXsvJrbmVOrby2txOiqudZkk5mD3
  E5O/QZWPWQLgRu8ueYNpobAX9NRgNfZ7rZD+81vh5MfZiXfuZOuzv29iZhU0oqyZ9y75eHkLdrer
  NkwYOe5aUQKBgQDLzapDi1NxkBgsj9iiO4KUa7jvD4JjRqFy4Zhj/jbQvlvM0F/uFp7sxVcHGx4r
  11C+6iCbhX4u+Zuu0HGjT4d+hNXmgGyxR8fIUVxOlOtDkVJa5sOBZK73/9/MBeKusdmJPRhalZQf
  MUJRWIoEVDMhfg3tW/rBj5RYAtP2dTVUMQKBgDs8yr52dRmT+BWXoFWwaWB0NhYHSFz/c8v4D4Ip
  5DJ5M5kUqquxJWksySGQa40sbqnD05fBQovPLU48hfgr/zghn9hUjBcsoZOvoZR4sRw0UztBvA+7
  jzOz1hKAOyWIulR6Vca0yUrNlJ6G5R56+sRNkiOETupi2dLCzcqb0PoxAoGAZyNHvTLvIZN4iGSr
  jz5qkM4LIwBIThFadxbv1fq6pt0O/BGf2o+cEdq0diYlGK64cEVwBwSBnSg4vzlBqRIAUejLjwED
  AJyA4EE8Y5A9l04dzV7nJb5cRak6CrgXxay/mBJRFtaHxVlaZGxYPGSYE6UFS0+3EOmmevvDZQBf
  4qECgYEA0ZF6Vavz28+8wLO6SP3w8NmpHk7K9tGEvUfQ30SgDx4G7qPIgfPrbB4OP/E0qCfsIImi
  3sCPpjvUMQdVVZyPOIMuB+rV3ZOxkrzxEUOrpOpR48FZbL7RN90yRQsAsrp9e4iv8QwB3VxLe7X0
  TDqqnRyqrc/osGzuS2ZcHOKmCU8=
  -----END PRIVATE KEY-----`;
  const der = derFromPEM(data);

  const decoded = decodeDER(der);

  const [
    [privateKeyInfoType, [
      [versionType, version],
      [algorithmIdentifierType, algorithmIdentifier],
      [privateKeyType, privateKey], // Skip validation
    ]],
  ] = decoded;
  t.deepEqual(privateKeyInfoType, 'SEQUENCE');
  t.deepEqual(versionType, 'INTEGER');
  t.deepEqual(version, 0);
  t.deepEqual(algorithmIdentifierType, 'SEQUENCE');

  const [
    [algorithmIdentifierObjectIdentifierType, algorithmIdentifierObjectIdentifier],
    ...algorithmIdentifierParams
  ] = /** @type {import('../../utils/asn1/decoder.js').DecodedEntry[]} */ (algorithmIdentifier);

  t.deepEqual(algorithmIdentifierObjectIdentifierType, 'OBJECT_IDENTIFIER');

  t.deepEqual(algorithmIdentifierObjectIdentifier, '1.2.840.113549.1.1.1');
  t.deepEqual(algorithmIdentifierParams, [['NULL', null]]);
  t.deepEqual(privateKeyType, 'OCTET_STRING');

  const decodedPrivateKey = decodeDER(privateKey);

  const [
    [rsaPrivateKeyType, [
      [pkVersionType, pkVersion],
      [modulusType, modulus],
      [publicExponentType, publicExponent],
      [privateExponentType, privateExponent],
      [prime1Type, prime1],
      [prime2Type, prime2],
      [exponent1Type, exponent1],
      [exponent2Type, exponent2],
      [coefficientType, coefficient],
      ...otherPrimeInfos
    ]],
  ] = decodedPrivateKey;

  /* eslint-disable max-len, unicorn/numeric-separators-style */
  t.deepEqual(rsaPrivateKeyType, 'SEQUENCE');

  t.deepEqual(pkVersionType, 'INTEGER');
  t.deepEqual(pkVersion, 0);

  t.deepEqual(modulusType, 'INTEGER');
  t.deepEqual(modulus, 24720432375494021199989903049094584245473625999743480404880407885229276308395658144430572657425825865902926874377819773702195919209309443236159868819592950684825444049794585978121130051018652099016101800487989832694613422617274852518597222941897179341887476302155262350757540041493141831922423779735321529909251933729664162036683086280737340979592651994429967179140909210858054432968078380299664473855736210658698281129654644029658921218775544408366455390309765464198048029050146163968655420139672794772124452360623571874686826454291833364282388662182110480568130556547554378276908667404757841893880027405426494987649n);

  t.deepEqual(publicExponentType, 'INTEGER');
  t.deepEqual(publicExponent, 65_537);

  t.deepEqual(privateExponentType, 'INTEGER');
  t.deepEqual(privateExponent, 537601602807160134203360076303798712114702922870048910494160570951111983437461461012095055922549984213164266409920924553596513936449155194353370661384025099768794179348608170427653701042378105560564247541778041549781005852957428377132470085569051907426722700148721907707358956683066060331529281048381326739135315300700204976302824041384232351719560622316589905032107023672984584921951884896659309087096246064531849304562978704479665338313753340432274199245344534646784889358140180459732995439354652385798118826178294764048745504826148439605473078996955519648782827839929089445335646662898138077876127909101068905153n);

  t.deepEqual(prime1Type, 'INTEGER');
  t.deepEqual(prime1, 172730522672832511312615456615164026267401702071535254285602518183124935875766826389191820885615543180956192028724241995897007732357681080942035736442388155348163730683028884464235754922736872383806122616917904330974408793275348676861485445004968383805542968248824264605793198888737640475349118595817597196881n);

  t.deepEqual(prime2Type, 'INTEGER');
  t.deepEqual(prime2, 143115599912337396299655738910154055837199420748291524161254413807088246764326512358210846521408737408474376157135323727862017133449294534644237793883413255423228417739555092667358572700545216611751893321150393766155754514346573944446765923212241980135834255097233720070720958537872314935620686196904633390129n);

  t.deepEqual(exponent1Type, 'INTEGER');
  t.deepEqual(exponent1, 41597965108950905992752334585915342883842731034301858772749203419202295847036449958048346873333691167203741074345098363081045410070666653958956772941547709780125244691857193394556249446046600497941804374060687612429148328185068406654329993416137693235926036710120899160370997422233946924980318580310193273393n);

  t.deepEqual(exponent2Type, 'INTEGER');
  t.deepEqual(exponent2, 72425835584365809934455074792776132808895066733873028828481070057004269224799015958503149911180587834192306019920810332457568400262131353830825192974003754052928783782444790017938178772087258405867880645883607117327948398962700023521391559107942345746449775005796016904428510778141709220055780374544746799777n);

  t.deepEqual(coefficientType, 'INTEGER');
  t.deepEqual(coefficient, 147163845909714606281364564768480977272259162236872889253965353593111652078679224140678153812970301531815782841112062442489852209324743981966757837977358829464159089249553360634954008950871807025107502742795340955486421112634443677307748261061809216350877339143586403642241383203937000692967281032895314397519n);

  t.deepEqual(otherPrimeInfos.length, 0);
  /* eslint-enable max-len, unicorn/numeric-separators-style */
});
