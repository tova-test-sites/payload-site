import type { CollectionConfig } from 'payload'

import {
  FixedToolbarFeature,
  InlineToolbarFeature,
  lexicalEditor,
} from '@payloadcms/richtext-lexical'
import path from 'path'
import { fileURLToPath } from 'url'

import { anyone } from '../access/anyone'
import { authenticated } from '../access/authenticated'

const filename = fileURLToPath(import.meta.url)
const dirname = path.dirname(filename)

// Uploads live in public/media and are committed, because Vercel's disk does not persist.
// Point every file URL at the static /media/<filename> path so Next serves them from public/.
const staticMediaURL = (filename?: string | null): string | undefined =>
  filename ? `/media/${encodeURIComponent(filename)}` : undefined

export const Media: CollectionConfig = {
  slug: 'media',
  folders: true,
  hooks: {
    afterRead: [
      ({ doc }) => {
        if (!doc?.filename) return doc
        doc.url = staticMediaURL(doc.filename)
        if (doc.thumbnailURL) doc.thumbnailURL = staticMediaURL(doc.sizes?.thumbnail?.filename ?? doc.filename)
        for (const size of Object.values(doc.sizes ?? {}) as Array<{ filename?: string | null; url?: string | null }>) {
          if (size?.filename) size.url = staticMediaURL(size.filename)
        }
        return doc
      },
    ],
  },
  access: {
    create: authenticated,
    delete: authenticated,
    read: anyone,
    update: authenticated,
  },
  fields: [
    {
      name: 'alt',
      type: 'text',
      //required: true,
    },
    {
      name: 'caption',
      type: 'richText',
      editor: lexicalEditor({
        features: ({ rootFeatures }) => {
          return [...rootFeatures, FixedToolbarFeature(), InlineToolbarFeature()]
        },
      }),
    },
  ],
  upload: {
    // Upload to the public/media directory in Next.js making them publicly accessible even outside of Payload
    staticDir: path.resolve(dirname, '../../public/media'),
    adminThumbnail: 'thumbnail',
    focalPoint: true,
    imageSizes: [
      {
        name: 'thumbnail',
        width: 300,
      },
      {
        name: 'square',
        width: 500,
        height: 500,
      },
      {
        name: 'small',
        width: 600,
      },
      {
        name: 'medium',
        width: 900,
      },
      {
        name: 'large',
        width: 1400,
      },
      {
        name: 'xlarge',
        width: 1920,
      },
      {
        name: 'og',
        width: 1200,
        height: 630,
        crop: 'center',
      },
    ],
  },
}
