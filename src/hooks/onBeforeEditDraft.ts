import host from '@plugin-host';
import { pgpDecrypt, PgpKeyLockedError } from '../pgp/decrypt.ts';

import {config, settings} from '../shared.ts';
import { unlockedDecryptMaps } from '../util.ts';

const PGP_MESSAGE_MARKER = '-----BEGIN PGP MESSAGE-----';

export async function onBeforeEditDraft(email: any): Promise<any> {
  try {
    return await decryptDraft(email);
  } catch (err) {
    if (!(err instanceof PgpKeyLockedError)) {
      host.log.warn('onBeforeEditDraft: draft left as stored', err);
      host.toast.warning(host.i18n.t('warn.draft_not_decrypted'));
    }
    return email;
  }
}

async function decryptDraft(email: any): Promise<any> {
  if(settings().encryptDrafts !== true && await config('forceDraftAndAttachmentsEncryption') !== true) return email;

  const indexText = email?.textBody?.[0]?.partId;
  const indexHtml = email?.htmlBody?.[0]?.partId;
  const encryptedText = indexText != null ? email.bodyValues?.[indexText]?.value : undefined;
  const encryptedHtml = indexHtml != null ? email.bodyValues?.[indexHtml]?.value : undefined;
  const textIsPgp = typeof encryptedText === 'string' && encryptedText.includes(PGP_MESSAGE_MARKER);
  const htmlIsPgp = typeof encryptedHtml === 'string' && encryptedHtml.includes(PGP_MESSAGE_MARKER);
  if (!textIsPgp && !htmlIsPgp) return email;

  const modifiedEmail = { ...email, bodyValues: { ...email.bodyValues } };
  const { keyRecords, unlockedKeys } = await unlockedDecryptMaps();
  const decoder = new TextDecoder('utf-8');
  const encoder = new TextEncoder();

  if (textIsPgp) {
    const decryptedTextResult = await pgpDecrypt({
      cmsBytes: encoder.encode(encryptedText),
      keyRecords,
      unlockedKeys,
      knownPublicKeys: []
    });

    let text = decoder.decode(decryptedTextResult.mimeBytes);
    if (modifiedEmail.hasAttachment) {
      const metadataRegex = /<--PGP_METADATA_START-->([\s\S]*?)<--PGP_METADATA_END-->/;
      const match = text.match(metadataRegex);

      if (match && match[1]) {
        try {
          const metadataMap: Record<string, { originalName: string; originalType: string }> = JSON.parse(match[1].trim());

          if (modifiedEmail.bodyStructure && Array.isArray(modifiedEmail.bodyStructure.subParts)) {
            modifiedEmail.bodyStructure = {
              ...modifiedEmail.bodyStructure,
              subParts: modifiedEmail.bodyStructure.subParts.map((subPart: any, index: number) => {
                if (index >= 1 && subPart.blobId) {
                  const meta = metadataMap[subPart.blobId];
                  if (meta) {
                    return {
                      ...subPart,
                      name: meta.originalName,
                      type: meta.originalType
                    };
                  }
                }
                return subPart;
              }),
            };
          }

          if (Array.isArray(modifiedEmail.attachments)) {
            modifiedEmail.attachments = modifiedEmail.attachments.map((attachment: any) => {
              if (attachment.blobId && metadataMap[attachment.blobId]) {
                return {
                  ...attachment,
                  name: metadataMap[attachment.blobId].originalName,
                  type: metadataMap[attachment.blobId].originalType
                };
              }
              return attachment;
            });
          }

          text = text.replace(metadataRegex, '').trim();

        } catch (e) {
          throw new Error('Failed to parse attachment metadata: ' + (e instanceof Error ? e.message : String(e)));
        }
      }
    }

    modifiedEmail.bodyValues[indexText] = { ...modifiedEmail.bodyValues[indexText], value: text };
  }

  if (htmlIsPgp) {
    const decryptedHtmlResult = await pgpDecrypt({
      cmsBytes: encoder.encode(encryptedHtml),
      keyRecords,
      unlockedKeys,
      knownPublicKeys: []
    });

    modifiedEmail.bodyValues[indexHtml] = {
      ...modifiedEmail.bodyValues[indexHtml],
      value: decoder.decode(decryptedHtmlResult.mimeBytes),
    };
  }
  return modifiedEmail;
}
