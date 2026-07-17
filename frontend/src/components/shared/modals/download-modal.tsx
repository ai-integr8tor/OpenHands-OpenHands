import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  BaseModalDescription,
  BaseModalTitle,
} from "#/components/shared/modals/confirmation-modals/base-modal";
import { ModalBackdrop } from "#/components/shared/modals/modal-backdrop";
import { ModalBody } from "#/components/shared/modals/modal-body";
import { BrandButton } from "#/components/features/settings/brand-button";
import { I18nKey } from "#/i18n/declaration";
import V1ConversationService from "#/api/conversation-service/v1-conversation-service.api";
import { downloadBlob } from "#/utils/utils";
import {
  displayErrorToast,
  displaySuccessToast,
} from "#/utils/custom-toast-handlers";
import { retrieveAxiosErrorMessage } from "#/utils/retrieve-axios-error-message";

interface DownloadModalProps {
  conversationId: string;
  onClose: () => void;
}

export function DownloadModal({ conversationId, onClose }: DownloadModalProps) {
  const { t } = useTranslation();
  const [filePath, setFilePath] = useState("");
  const [isDownloading, setIsDownloading] = useState(false);

  const handleDownload = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!filePath.trim()) return;

    setIsDownloading(true);
    try {
      const { blob, filename } =
        await V1ConversationService.downloadConversationFile(
          conversationId,
          filePath.trim(),
        );
      downloadBlob(blob, filename);
      displaySuccessToast(t("DOWNLOAD$SUCCESS_MESSAGE" as I18nKey));
      onClose();
    } catch (error) {
      const errorMsg = retrieveAxiosErrorMessage(error);
      displayErrorToast(errorMsg || t("DOWNLOAD$ERROR_MESSAGE" as I18nKey));
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <ModalBackdrop onClose={onClose}>
      <ModalBody className="items-start border border-tertiary">
        <form onSubmit={handleDownload} className="w-full flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <BaseModalTitle title={t("DOWNLOAD$TITLE" as I18nKey)} />
            <BaseModalDescription>
              {t("DOWNLOAD$INSTRUCTION" as I18nKey)}
            </BaseModalDescription>
          </div>

          <div className="flex flex-col gap-1.5 w-full">
            <label
              htmlFor="download-path"
              className="text-xs font-semibold text-[#9299AA]"
            >
              {t("DOWNLOAD$PATH_LABEL" as I18nKey)}
            </label>
            <input
              id="download-path"
              type="text"
              required
              disabled={isDownloading}
              value={filePath}
              onChange={(e) => setFilePath(e.target.value)}
              placeholder={t("DOWNLOAD$PATH_PLACEHOLDER" as I18nKey)}
              className="w-full p-2.5 bg-neutral-900 border border-neutral-700 rounded text-sm text-white placeholder-neutral-500 focus:outline-none focus:border-primary disabled:opacity-50"
            />
          </div>

          <div
            className="flex flex-col gap-2 w-full mt-2"
            onClick={(event) => event.stopPropagation()}
          >
            <BrandButton
              type="submit"
              variant="primary"
              isDisabled={isDownloading || !filePath.trim()}
              className="w-full flex items-center justify-center gap-2"
              testId="confirm-download-button"
            >
              {isDownloading
                ? t("DOWNLOAD$DOWNLOADING" as I18nKey)
                : t("DOWNLOAD$BUTTON" as I18nKey)}
            </BrandButton>
            <BrandButton
              type="button"
              variant="secondary"
              isDisabled={isDownloading}
              onClick={onClose}
              className="w-full"
              testId="cancel-download-button"
            >
              {t("DOWNLOAD$CANCEL" as I18nKey)}
            </BrandButton>
          </div>
        </form>
      </ModalBody>
    </ModalBackdrop>
  );
}
